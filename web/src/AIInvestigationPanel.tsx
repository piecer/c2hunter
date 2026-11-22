import { InvestigationReceiptContext, useReceiptSurface } from './investigationReceiptContext';
import { InvestigationActivityContext } from './investigationActivityContext';
import { useReportLanguage } from './reportLanguageContext';
import { useInvestigationText } from './investigationLanguage';
import { useEffect, useRef, useState } from 'react';
import { captureRequest, investigationApi } from './investigationApi';
import { literalIP, normalizeScope } from './investigationContract';
import { investigationError, investigationScopeMessages, useInvestigationOwner } from './investigationLifecycle';
import { Coverage, InvestigationPages, ScopeDetails } from './InvestigationResult';
import InvestigationRunView from './InvestigationRunView';
import { emptyScope, type InvestigationCapabilities, type InvestigationRun, type Page, type Scope, type SourcePreview } from './investigationTypes';
import './investigation.css';

export type InvestigationSelection = { ip: string; side?: Scope['endpoint_side']; sequence: number };
/** Keep the existing analysis page quiet until investigation is explicitly opened. */
export function AIInvestigationEntry({ jobId, selection, visible = true, sourceAvailable = true }: { jobId: string; selection?: InvestigationSelection; visible?: boolean; sourceAvailable?: boolean }) {
  const l = useInvestigationText();
  const [opened, setOpened] = useState(false);
  return <div id="ip-investigation-entry">{opened || selection ? <AIInvestigationPanel jobId={jobId} selection={selection} visible={visible} sourceAvailable={sourceAvailable}/> : visible ? <section className="panel investigation-panel" aria-label={l("IP 조사 시작점", "IP investigation entry")}><h2>{l("IP 조사", "IP investigation")}</h2><p>{l("후보 또는 flow의 IP를 선택하거나 직접 주소를 입력하세요.", "Select a candidate or flow endpoint, or enter any IP.")}</p><button type="button" onClick={() => setOpened(true)}>{l("IP 조사 열기", "Open IP investigation")}</button></section> : null}</div>;
}
export default function AIInvestigationPanel({ jobId, selection, visible = true, sourceAvailable = true }: { jobId: string; selection?: InvestigationSelection; visible?: boolean; sourceAvailable?: boolean }) {
  // Job departure retires authority; endpoint navigation does not own admission.
  return <InvestigationSession key={jobId} jobId={jobId} selection={selection} visible={visible} sourceAvailable={sourceAvailable}/>;
}
function InvestigationSession({ jobId, selection, visible = true, sourceAvailable = true }: { jobId: string; selection?: InvestigationSelection; visible?: boolean; sourceAvailable?: boolean }) {
  const l = useInvestigationText();
  const receiptSurface = useReceiptSurface();
  const [formOpen, setFormOpen] = useState(false);
  const [recoveryOpen, setRecoveryOpen] = useState(false);
  const shown = visible || recoveryOpen;
  const [scope, setScope] = useState<Scope>(() => ({ ...emptyScope(selection?.ip), endpoint_side: selection?.side ?? 'either' }));
  const displayLanguage = useReportLanguage();
  const [language, setLanguage] = useState<'ko' | 'en'>(displayLanguage);
  const [question, setQuestion] = useState('관측된 사실과 C2 가설, 반대 근거를 설명해 주세요.');
  const [allowRemote, setAllowRemote] = useState(false);
  const [capability, setCapability] = useState<InvestigationCapabilities>();
  const [capabilityError, setCapabilityError] = useState('');
  const [capabilityReason, setCapabilityReason] = useState<string | null>(null);
  const [preview, setPreview] = useState<SourcePreview>();
  const [previewBusy, setPreviewBusy] = useState(false);
  const [error, setError] = useState('');
  const [captured, setCaptured] = useState<string>();
  const [pending, setPending] = useState(false);
  const pendingRef = useRef(false);
  const [ackUncertain, setAckUncertain] = useState(false);
  const [selected, setSelected] = useState<InvestigationRun>();
  const navigation = useRef(0);
  const [active, setActive] = useState<InvestigationRun>();
  const [cancelling, setCancelling] = useState<InvestigationRun>();
  const lastSelection = useRef(selection?.sequence);
  const [deferredSelection, setDeferredSelection] = useState<InvestigationSelection>();
  const [historyEpoch, setHistoryEpoch] = useState(0);
  const capabilityOwner = useInvestigationOwner();
  const previewOwner = useInvestigationOwner();
  const submitOwner = useInvestigationOwner();
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    void capabilityOwner.request(signal => investigationApi.capabilities(signal), value => { setCapability(value.document); setCapabilityReason(value.unavailableReason); }, value => setCapabilityError(investigationError(value)));
  }, [capabilityOwner]);
  useEffect(() => {
    if (lastSelection.current === selection?.sequence) return;
    lastSelection.current = selection?.sequence;
    navigation.current += 1;
    if (!selection) return;
    if (pendingRef.current || captured) { setDeferredSelection(selection); return; }
    previewOwner.cancel(); setPreview(undefined); setPreviewBusy(false); setDeferredSelection(undefined);
    setScope({ ...emptyScope(selection.ip), endpoint_side: selection.side ?? 'either' });
    setFormOpen(true);
  }, [selection, captured, previewOwner]);
  useEffect(() => { if (visible) setRecoveryOpen(false); }, [visible]);
  useEffect(() => { if (formOpen && selection) input.current?.focus(); }, [formOpen, selection]);
  const invalidate = () => {
    navigation.current += 1;
    previewOwner.cancel(); setPreview(undefined); setPreviewBusy(false); setError(''); setSelected(undefined);
  };
  const editScope = (changes: Partial<Scope>) => { invalidate(); setScope(value => ({ ...value, ...changes })); };
  const prepare = () => {
    if (!sourceAvailable) return;
    invalidate(); setPreviewBusy(true);
    // Display retains the literal user input; the captured scope uses the same
    // canonical IPv6 representation returned by the producer.
    let normalized: Scope;
    try { normalized = normalizeScope(scope); }
    catch (value) { setError(investigationError(value)); setPreviewBusy(false); return; }
    void previewOwner.request(signal => investigationApi.preview(jobId, normalized, signal), value => { setPreview(value); setPreviewBusy(false); }, value => { setError(investigationError(value)); setPreviewBusy(false); });
  };
  const submit = () => {
    if (pendingRef.current || (!captured && (!preview || !sourceAvailable))) return;
    if (active && !captured) { setError(l("먼저 활성 조사를 확인하세요.", "Review the active investigation before another admission.")); return; }
    const startedAt = navigation.current;
    let body = captured;
    try { body ??= captureRequest(preview!.scope, question, language, preview!.source.source_sha256, allowRemote); }
    catch (value) { setError(investigationError(value)); return; }
    setCaptured(body); pendingRef.current = true; setPending(true); setError('');
    // This is the only admission POST. Explicit retry reuses this exact string/key.
    void submitOwner.request(signal => investigationApi.create(jobId, body!, signal), run => {
      pendingRef.current = false; setPending(false); setAckUncertain(false); setCaptured(undefined); setPreview(undefined);
      setActive(run);
      if (navigation.current === startedAt) setSelected(run);
      setHistoryEpoch(value => value + 1);
    }, value => { pendingRef.current = false; setPending(false); setAckUncertain(true); setError(investigationError(value)); });
  };
  const choose = (run: InvestigationRun) => {
    navigation.current += 1;
    setSelected(run);
  };
  const resetDraft = () => { submitOwner.cancel(); setCaptured(undefined); setAckUncertain(false); setPending(false); pendingRef.current = false; invalidate(); };
  const available = sourceAvailable && capability?.availability === 'CONFIGURED_NOT_PROBED';

  const activity = <section aria-label={l('보존된 조사 작업', 'Retained investigation work')}>
    {(pending || captured) && <><p role="status">{pending ? l('수락 확인 중', 'Awaiting admission acknowledgment') : l('수락 여부 미확인', 'Admission is unconfirmed')}</p><p>Job {jobId} · IP {scope.target_ip}</p><button type="button" onClick={() => { setRecoveryOpen(!visible); setFormOpen(true); }}>{l('수락 복구', 'Recover admission')}</button></>}
    {[...(active ? [active] : []), ...(cancelling && cancelling.id !== active?.id ? [cancelling] : [])].map(run => <p key={run.id}><button type="button" onClick={() => { choose(run); setRecoveryOpen(!visible); }}>{l('활성 조사로 돌아가기', 'Return to active investigation')} {run.id}</button></p>)}
  </section>;
  return <InvestigationReceiptContext.Provider value={receiptSurface}><InvestigationActivityContext.Provider value={activity}>
    {!visible && recoveryOpen && <button type="button" onClick={() => setRecoveryOpen(false)}>{l('복구 화면 닫기', 'Close recovery')}</button>}
    {[...(active ? [active] : []), ...(cancelling && cancelling.id !== active?.id ? [cancelling] : []), ...(selected && selected.id !== active?.id && selected.id !== cancelling?.id ? [selected] : [])].map(run => <InvestigationRunView key={run.id} initial={selected?.id===run.id?selected:run} visible={shown && selected?.id === run.id} onCancelStart={setCancelling} canCancel={!cancelling || cancelling.id === run.id} onRelease={active?.id === run.id || cancelling?.id === run.id ? () => { setActive(current => current?.id === run.id ? undefined : current); setCancelling(current => current?.id === run.id ? undefined : current); } : undefined}/>)}
    {[...(active ? [active] : []), ...(cancelling && cancelling.id !== active?.id ? [cancelling] : [])].filter(run => !shown || run.id !== selected?.id).map(run => <button key={run.id} type="button" onClick={() => { choose(run); setRecoveryOpen(!visible); }}>{l("활성 조사로 돌아가기", "Return to active investigation")} <code>{run.id}</code></button>)}
    {deferredSelection && <section><p role="status">{deferredSelection.ip} {l('선택이 보류되었습니다. 캡처된 조사부터 복구하세요.', 'Selection deferred; recover the captured investigation first.')}</p><button type="button" disabled={pending || Boolean(captured)} onClick={() => { if (pendingRef.current || captured) return; invalidate(); setScope({ ...emptyScope(deferredSelection.ip), endpoint_side: deferredSelection.side ?? 'either' }); setDeferredSelection(undefined); setFormOpen(true); setRecoveryOpen(!visible); }}>{l('보류한 대상 적용', 'Apply deferred target')}</button></section>}
    <InvestigationHistory jobId={jobId} epoch={historyEpoch} selectedId={selected?.id} choose={choose} visible={shown}/>
    {!shown ? <section aria-label={l("IP 조사 상태", "IP investigation status")}>
    {(pending || ackUncertain) && <button type="button" onClick={() => { setRecoveryOpen(!visible); setFormOpen(true); }}>{l("수락 복구", "Recover admission")}</button>}
    {pending && <p role="status">{l("수락 확인 중", "Awaiting admission acknowledgment")}</p>}
    {ackUncertain && <p role="alert">{l("수락 여부가 불확실합니다.", "Admission is unconfirmed. Recover the exact request in AI investigation.")}</p>}
    {error && <p role="alert">{error}</p>}
  </section> : <section id="ip-investigation" className="panel investigation-panel" aria-label={l("IP 조사", "IP investigation")}>
    <header><p className="eyebrow">IP INVESTIGATION</p><h2>{l("IP 조사", "IP investigation")}</h2><p className="muted">{l("선택 작업의 보존 자료로만 조사합니다. 후보 여부·상위 5개 제한 없이 내부 IP와 IPv6도 선택할 수 있습니다.", "Investigate retained evidence for any IP, including internal and IPv6 addresses, without changing candidates or scores.")}</p><p className="record-id">Job {jobId}</p></header>

    <button type="button" aria-expanded={formOpen} aria-controls="ip-investigation-draft" onClick={() => setFormOpen(!formOpen)}>{l("새 조사 요청", "New investigation request")}</button>
    {formOpen && <div id="ip-investigation-draft">
    {!sourceAvailable && <p className="warning">{l('현재 출처를 사용할 수 없어 새 조사는 차단됩니다. 저장 이력과 동일 요청 복구는 별개입니다.', 'Current source is unavailable; new investigation is blocked. Saved history and exact-request recovery are independent.')}</p>}
    <div className="investigation-capability" role="status">{capability ? capability.availability === 'CONFIGURED_NOT_PROBED' ? l("설정됨 · 연결/모델 미검증", "CONFIGURED_NOT_PROBED — configuration is not a readiness guarantee.") : l("조사 시작 불가", "UNAVAILABLE — history remains readable.") : capabilityError || l("기능 상태 확인 중", "Checking availability")}</div>
    {capability?.availability === 'UNAVAILABLE' && <p>{l("기능 사유", "Capability reason:")} {capabilityReason ?? l("보고되지 않음", "Not reported")}</p>}
    {capabilityReason === 'DISPATCH_UNAVAILABLE' && <p className="muted">{l("관리자가 조사 실행기를 구성해야 합니다. C2HUNTER_AI_INVESTIGATION_INLINE_ENABLED는 기본 false이며, 승인된 inline 또는 AI-worker 실행 모드가 필요합니다.", "An administrator must configure dispatch. C2HUNTER_AI_INVESTIGATION_INLINE_ENABLED defaults to false; an enabled inline or AI-worker mode is required. This screen does not change configuration.")}</p>}
    {(capabilityError || capability?.availability === 'UNAVAILABLE') && <p className="warning">{l("새 조사에는 지원되는 공급자·런타임이 필요합니다. host.docker.internal은 이 조사 경로에서 지원되지 않습니다. 기존 AI 기능과 저장 이력은 별개입니다.", "A supported provider/runtime is required; host.docker.internal is unsupported by this investigation path. Legacy AI and saved history are separate.")}</p>}
    <form className="investigation-form" onSubmit={event => { event.preventDefault(); if (literalIP(scope.target_ip) && available && !captured) prepare(); }}>
      <fieldset disabled={pending || Boolean(captured)}><legend>{l("조사 대상과 질문", "Target & question")}</legend>
        <label>{l("대상 IP", "Target IP")}<input ref={input} value={scope.target_ip} maxLength={45} autoComplete="off" placeholder="2001:db8::1" onChange={event => editScope({ target_ip: event.target.value })} required/></label>
        {scope.target_ip && !literalIP(scope.target_ip) && <p role="alert">{l("단일 IP 주소를 입력하세요.", "Enter one literal IP address, not a hostname or CIDR.")}</p>}
        <label>{l("질문", "Question")}<textarea value={question} onChange={event => { invalidate(); setQuestion(event.target.value); }} rows={3} maxLength={2000} required/></label>
        <label>{l("언어", "Language")}<select value={language} onChange={event => { invalidate(); setLanguage(event.target.value as 'ko' | 'en'); }}><option value="ko">한국어</option><option value="en">English</option></select></label>
        <details><summary>{l("범위 제한", "Scope filters")}</summary><div className="investigation-filters"><label>{l("엔드포인트", "Endpoint")}<select value={scope.endpoint_side} onChange={event => editScope({ endpoint_side: event.target.value as Scope['endpoint_side'] })}><option value="either">{l("양쪽", "Either")}</option><option value="source">{l("출발", "Source")}</option><option value="destination">{l("도착", "Destination")}</option></select></label><label>{l("센서", "Sensor")}<input value={scope.sensor_id ?? ''} maxLength={200} placeholder="All sensors" onChange={event => editScope({ sensor_id: event.target.value || null })}/></label><label>{l("방향", "Direction")}<select value={scope.traffic_direction ?? ''} onChange={event => editScope({ traffic_direction: (event.target.value || null) as Scope['traffic_direction'] })}><option value="">{l("전체", "All")}</option>{['INBOUND', 'OUTBOUND', 'INTERNAL', 'UNKNOWN'].map(value => <option key={value}>{value}</option>)}</select></label><label>{l("시작 UTC", "Start UTC")}<input value={scope.start_time ?? ''} placeholder="2026-01-01T00:00:00Z" maxLength={40} onChange={event => editScope({ start_time: event.target.value || null })}/></label><label>{l("종료 UTC", "End UTC")}<input value={scope.end_time ?? ''} placeholder="2026-01-01T01:00:00Z" maxLength={40} onChange={event => editScope({ end_time: event.target.value || null })}/></label></div></details>
        <label className="check"><input type="checkbox" checked={allowRemote} disabled={!capability?.remote_server_allowed} onChange={event => { invalidate(); setAllowRemote(event.target.checked); }}/>{l("원격 모델 전송에 명시적 동의", "Explicitly allow remote model transfer")}</label>
        <button disabled={!available || !literalIP(scope.target_ip) || !question.trim() || previewBusy}>{previewBusy ? l("범위 읽는 중", "Reading scope") : l("범위 미리보기", "Preview scope")}</button>
      </fieldset>
    </form>
    {preview && <section aria-label={l("출처 미리보기", "Source preview")}><h3>{preview.scope.target_ip} · {preview.status}</h3><Coverage counts={preview.counts}/>{preview.status !== 'OBSERVED' && <p className="warning">{investigationScopeMessages[preview.status]}</p>}<p className="muted">{l("일치 없음은 IP나 C2의 부재를 뜻하지 않습니다. 확인된 일치·확인 불가·범위 누락을 구분하고 출처 제한을 읽으세요.", "No matches does not mean no IP or C2. Distinguish known matches, unavailable evidence and unknown scope; read the source limitations.")}</p><p className="record-id">Source {preview.source.source_sha256}</p><ScopeDetails jobId={jobId} scope={preview.scope} source={preview.source}/><InvestigationPages items={preview.limitations} label="preview limitations">{value => <p>{value}</p>}</InvestigationPages><p>{l("이 범위와 출처 해시로 제출합니다.", "Submission is bound to this scope and source digest.")}</p>{!captured && <button type="button" onClick={submit} disabled={pending || !available || preview.counts.matched === 0}>{l("조사 시작", "Start investigation")}</button>}</section>}
    </div>}
    {pending && <p role="status">{l("수락 확인 중", "Awaiting admission acknowledgment")}</p>}
    {error && <p role="alert">{error}</p>}
    {ackUncertain && <section className="warning"><p>{l("수락 여부가 불확실합니다. 재시도는 동일 본문과 키를 사용하며 자동 제출하지 않습니다.", "Admission is unconfirmed. Explicit retry sends the exact captured body and key; no automatic POST retries.")}</p><button type="button" onClick={submit} disabled={pending}>{l("동일 요청 재시도", "Retry captured request")}</button><button type="button" className="secondary" disabled={pending} onClick={resetDraft}>{l("캡처 해제", "Release captured draft")}</button><p>{l("초안 해제·화면 전환은 서버 조사를 취소하지 않습니다. 이력에서 확인하세요.", "Releasing the draft or leaving does not cancel server work; check history.")}</p></section>}
  </section>}</InvestigationActivityContext.Provider></InvestigationReceiptContext.Provider>;
}
function InvestigationHistory({ jobId, epoch, selectedId, choose, visible }: { jobId: string; epoch: number; selectedId?: string; choose: (run: InvestigationRun) => void; visible: boolean }) {
  const l = useInvestigationText();
  const owner = useInvestigationOwner();
  const [after, setAfter] = useState<string | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [page, setPage] = useState<Page<InvestigationRun, string>>();
  const [error, setError] = useState('');
  useEffect(() => {
    setPage(undefined); setError('');
    void owner.request(signal => investigationApi.history(jobId, after, signal), setPage, value => setError(investigationError(value)));
    return () => owner.cancel();
  }, [jobId, epoch, after, refresh, owner]);
  if (!visible) return null;
  return <section className="panel investigation-panel" aria-label={l("조사 이력", "Investigation history")}><h3>{l("조사 이력", "Investigation history")}</h3><p className="muted">{l("모델·현재 출처가 없어도 저장된 조사와 발급 근거를 읽을 수 있습니다.", "Saved investigations and issued evidence do not require the current model or source.")}</p>{error && <p role="alert">{error}  {l("— 이력을 확인하지 못했습니다.", "History could not be read.")}</p>}{!page && !error && <p role="status">{l("이력 읽는 중", "Loading history")}</p>}{page?.items.length === 0 && <p>{l("저장된 조사 없음", "No saved investigations")}</p>}<div className="investigation-history">{page?.items.map(run => <article key={run.id}><button type="button" className="secondary" aria-pressed={selectedId === run.id} onClick={() => choose(run)}>{run.target_ip} · {run.status}{' '}<small>{run.id}</small></button><p>{run.request.question}</p></article>)}</div><div className="investigation-actions"><button type="button" className="secondary" onClick={() => { setAfter(null); setRefresh(value => value + 1); }}>{l("처음 이력", "First history")}</button><button type="button" className="secondary" disabled={page?.next_cursor == null} onClick={() => setAfter(page!.next_cursor!)}>{l("다음 이력", "Next history")}</button><button type="button" className="secondary" onClick={() => setRefresh(value => value + 1)}>{l("이력 다시 읽기", "Retry history read")}</button></div></section>;
}
