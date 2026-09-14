import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from './api';
import { useReportLanguage } from './reportLanguageContext';
import { choose } from './reportTranslations';

type Interpretation = { schema_version: 'network-interpretation-v1'; kind: 'MODEL_INTERPRETATION'; language: 'ko' | 'en'; summary: string; possible_causes: { hypothesis: string; issue_ids: string[]; uncertainty: string }[]; prioritized_checks: { priority: string; check: string; issue_ids: string[] }[]; correlations: { interpretation: string; issue_ids: string[] }[]; limitations: string[] };
type FailureDiagnostic = { stage: 'MODEL_OUTPUT'; type: 'JSON_PARSE' | 'SCHEMA' | 'INVALID_CITATION' | 'LANGUAGE'; attempt_count: number; repair_count: number; output_bytes: number; provider_finish_reason?: 'stop' | 'length' | 'load' | 'unload' | 'tool_calls' | 'content_filter' | null };
type Run = { id: string; analysis_kind: string; status: string; language: 'ko' | 'en'; created_at?: string; completed_at?: string; provider?: string; model_name?: string; progress_percent?: number; error_code?: string; error_message?: string; failure_diagnostic?: FailureDiagnostic | null; network_interpretation?: Interpretation };
const activeStatuses = new Set(['QUEUED', 'PREPARING', 'ANALYZING', 'VALIDATING']);
const boundedText = (value: unknown) => typeof value === 'string' ? (value.length > 2000 ? `${value.slice(0, 2000)}…` : value) : '';
const boundedItems = <T,>(value: T[]) => Array.isArray(value) ? value.slice(0, 20) : [];
type Capabilities = { network_interpretation: boolean; available: boolean; provider: string; model_name: string; destination: string | null; remote: boolean; reason: string | null };
export default function NetworkAIInterpretation({ jobId, completed }: { jobId: string; completed: boolean }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => choose(language, en, ko);
  const client = useQueryClient();
  const capabilities = useQuery<Capabilities, Error>({ queryKey: ['ai-capabilities'], queryFn: () => api.get('/ai-capabilities'), retry: false });
  const config = capabilities.data;
  const [consentedDestination, setConsentedDestination] = useState<string | null>(null);
  const allowRemote = Boolean(config?.remote && config.destination && consentedDestination === config.destination);
  const runs = useQuery<{ items: Run[] }, Error>({
    queryKey: ['ai-runs', jobId], queryFn: () => api.get(`/analysis-jobs/${jobId}/ai-runs`), retry: false,
  });
  const [submittedRun, setSubmittedRun] = useState<Run>();
  const saved = runs.data?.items?.find(run => run.analysis_kind === 'NETWORK_ANOMALY');
  const latest = submittedRun ?? saved;
  const run = useQuery<Run, Error>({
    queryKey: ['ai-run', latest?.id], queryFn: () => api.get(`/ai-runs/${latest?.id}`), enabled: Boolean(latest?.id), retry: false,
    refetchInterval: query => !query.state.error && activeStatuses.has(query.state.data?.status ?? latest?.status ?? '') ? 2000 : false,
  });
  const current = run.data ?? latest;
  const active = Boolean(current && activeStatuses.has(current.status));
  const canStart = completed && config?.available === true && config.network_interpretation === true && (!config.remote || allowRemote) && !capabilities.isError && runs.isSuccess && !runs.isFetching && !run.isError && !run.isFetching && !active;
  const start = useMutation({
    mutationFn: () => api.post<Run>(`/analysis-jobs/${jobId}/ai-runs`, { idempotency_key: `web-${jobId}-${Date.now()}`, analysis_kind: 'NETWORK_ANOMALY', language, allow_remote: allowRemote }),
    onSuccess: async created => { setSubmittedRun(created); await client.invalidateQueries({ queryKey: ['ai-runs', jobId] }); },
  });
  const cancel = useMutation({
    mutationFn: () => api.post(`/ai-runs/${current?.id}/cancel`, { reason: 'operator requested from web console' }),
    onSuccess: async () => { await Promise.all([client.invalidateQueries({ queryKey: ['ai-run', current?.id] }), client.invalidateQueries({ queryKey: ['ai-runs', jobId] })]); },
  });
  const result = current?.status === 'COMPLETED' && current.network_interpretation?.schema_version === 'network-interpretation-v1' && current.network_interpretation.kind === 'MODEL_INTERPRETATION' ? current.network_interpretation : undefined;
  // Lookup only static labels; never echo unknown diagnostic values from older/newer servers.
  const failureLabels = new Map<string, string>([
    ['JSON_PARSE', t('Invalid JSON response', 'JSON 응답 해석 실패')],
    ['SCHEMA', t('Response schema mismatch', '응답 구조 검증 실패')],
    ['INVALID_CITATION', t('Invalid issue references', '이슈 참조 검증 실패')],
    ['LANGUAGE', t('Requested language mismatch', '요청 언어 불일치')],
  ]);
  const failureLabel = current?.status === 'FAILED' && current.error_code === 'MODEL_OUTPUT_INVALID' && current.failure_diagnostic?.stage === 'MODEL_OUTPUT' ? failureLabels.get(current.failure_diagnostic.type) : undefined;
  return <section className="panel" aria-labelledby="ai-network-heading">
    <div className="header-actions"><div><p className="eyebrow">{t('BOUNDED REPORT EVIDENCE', '제한된 보고서 증거')}</p><h2 id="ai-network-heading">{t('AI interpretation', 'AI 해석')}</h2></div><div className="ai-run-controls"><button type="button" disabled={!canStart || start.isPending} onClick={() => { if (canStart) start.mutate(); }}>{start.isPending ? t('Starting…', '시작 중…') : t('AI interpretation', 'AI 해석')}</button></div></div>
    <p>{t('Observed facts are in the deterministic report above. AI offers possible causes and next checks, not proven root causes or attack classifications.', '관찰된 사실은 위의 결정론적 보고서에 있습니다. AI는 가능한 원인과 다음 확인 사항을 제안하며 근본 원인이나 공격 여부를 확정하지 않습니다.')}</p>
    <p className="muted">{t('Manual only. The server sends a bounded report context to the configured model, not raw packets or payload. No inference runs on page load or language change.', '수동 실행 전용입니다. 서버는 원시 패킷이나 페이로드 대신 제한된 보고서 문맥을 설정된 모델에 보냅니다. 페이지 로드나 언어 변경으로 AI가 실행되지 않습니다.')}</p>
    {config && <p>{t('Provider / model / destination', '제공자 / 모델 / 전송 대상')}: {config.provider} · {config.model_name} · {config.destination ?? t('Not reported', '보고되지 않음')}</p>}
    {config?.remote && <label className="check"><input type="checkbox" checked={allowRemote} disabled={!config.destination || start.isPending} onChange={event => setConsentedDestination(event.target.checked ? config.destination : null)}/>{t('I consent to sending bounded report evidence to this remote model destination.', '이 원격 모델 대상에 제한된 보고서 증거를 전송하는 데 동의합니다.')}</label>}
    {!completed && <p className="muted">{t('A completed job with a saved network report is required.', '저장된 네트워크 보고서가 있는 완료된 작업에서만 실행할 수 있습니다.')}</p>}
    {capabilities.isLoading && <p role="status">{t('Checking AI availability…', 'AI 사용 가능 여부 확인 중…')}</p>}
    {(capabilities.isError || (config && (!config.available || !config.network_interpretation))) && <p role="alert" className="error-text">{t('AI interpretation is unavailable', 'AI 해석을 사용할 수 없습니다')}: {capabilities.error?.message ?? config?.reason ?? t('Not enabled', '비활성화됨')}</p>}
    {start.error && <p role="alert" className="error-text">{t('AI run could not be started', 'AI 실행을 시작하지 못했습니다')}: {start.error.message}</p>}
    {runs.isLoading && <p role="status">{t('Loading saved AI runs…', '저장된 AI 실행 조회 중…')}</p>}
    {(runs.isError || run.isError) && <p role="alert" className="error-text">{t('Saved AI run could not be read; status is unconfirmed', '저장된 AI 실행을 읽지 못했습니다. 상태를 확인할 수 없습니다')}: {boundedText(runs.error?.message ?? run.error?.message)}</p>}
    {(capabilities.isError || runs.isError || run.isError) && <button type="button" className="secondary" disabled={capabilities.isFetching || runs.isFetching || run.isFetching} onClick={() => { void capabilities.refetch(); void runs.refetch(); if (latest) void run.refetch(); }}>{t('Retry status lookup', '상태 조회 재시도')}</button>}
    {!runs.isLoading && !runs.isError && !current && <p className="muted">{t('No saved AI interpretation runs.', '저장된 AI 해석 실행이 없습니다.')}</p>}
    {current && <><div className="ai-run-summary" role="status"><span className={`badge ${active ? 'medium' : 'low'}`}>{t(({ QUEUED: 'Queued', PREPARING: 'Preparing', ANALYZING: 'Analyzing', VALIDATING: 'Validating', COMPLETED: 'Completed', FAILED: 'Failed', CANCELLED: 'Cancelled' } as Record<string, string>)[current.status] ?? boundedText(current.status), ({ QUEUED: '대기 중', PREPARING: '준비 중', ANALYZING: '해석 중', VALIDATING: '검증 중', COMPLETED: '완료', FAILED: '실패', CANCELLED: '취소됨' } as Record<string, string>)[current.status] ?? boundedText(current.status))}</span><span>{t('Requested language', '요청 언어')}: {current.language === 'ko' ? '한국어' : 'English'}</span><span>{t('Run created', '실행 생성')}: {boundedText(current.created_at) || '—'}</span></div>
      {typeof current.progress_percent === 'number' && Number.isFinite(current.progress_percent) && <progress aria-label={t('AI interpretation progress', 'AI 해석 진행률')} max="100" value={Math.max(0, Math.min(100, current.progress_percent))}/>}
      {active && <button type="button" className="secondary" disabled={cancel.isPending || run.isError} onClick={() => cancel.mutate()}>{cancel.isPending ? t('Requesting cancellation…', '취소 요청 중…') : t('Cancel AI run', 'AI 실행 취소')}</button>}
      {current.error_code && <p role="alert" className="error-text">{boundedText(current.error_code)}: {boundedText(current.error_message)}</p>}
      {failureLabel && <p className="error-text">{failureLabel}</p>}
      {current.status === 'COMPLETED' && !result && <p role="alert">{t('No validated interpretation is available for this run.', '이 실행의 검증된 해석 결과가 없습니다.')}</p>}
    </>}
    {cancel.error && <p role="alert" className="error-text">{t('Cancellation failed', '취소 실패')}: {boundedText(cancel.error.message)}</p>}
    {result && <article className="ai-assessment" style={{ overflowWrap: 'anywhere', maxHeight: 800, overflow: 'auto' }}>
      <h3>{t('AI-generated interpretation — analyst review required', 'AI 생성 해석 — 분석가 검토 필요')}</h3>
      <p className="muted">{t('Saved run provider / model', '저장된 실행 제공자 / 모델')}: {boundedText(current?.provider) || t('Not reported', '보고되지 않음')} · {boundedText(current?.model_name) || t('Not reported', '보고되지 않음')}</p>
      <p className="muted">{t('Generated language', '생성 언어')}: {result.language === 'ko' ? '한국어' : 'English'} · {t('Completed at', '완료 시각')}: {boundedText(current?.completed_at) || t('Not reported', '보고되지 않음')}</p>
      <p className="muted">{t('Existing AI output is not automatically translated. Changing report language changes labels only; use the manual button for a new interpretation.', '기존 AI 출력은 자동 번역되지 않습니다. 보고서 언어 변경은 항목명만 바꾸며 새 해석은 버튼으로 직접 요청하세요.')}</p>
      <p lang={result.language}>{boundedText(result.summary)}</p>
      <h4>{t('Possible causes (AI hypotheses)', '가능한 원인 (AI 가설)')}</h4>
      {boundedItems(result.possible_causes).map((cause, index) => <div key={index}><p lang={result.language}>{boundedText(cause?.hypothesis)}</p><strong>{t('Confidence / uncertainty', '신뢰도 / 불확실성')}</strong><p lang={result.language}>{boundedText(cause?.uncertainty)}</p><p>{t('Issue references', '이슈 참조')}: {boundedItems(cause?.issue_ids).map((id, i) => <code key={i}>{boundedText(id)} </code>)}</p></div>)}
      <h4>{t('Prioritized next checks', '우선순위별 다음 확인 사항')}</h4>
      <ol>{boundedItems(result.prioritized_checks).map((check, index) => <li key={index}><strong>{boundedText(check?.priority)}</strong><p lang={result.language}>{boundedText(check?.check)}</p>{boundedItems(check?.issue_ids).map((id, i) => <code key={i}>{boundedText(id)} </code>)}</li>)}</ol>
      <h4>{t('Possible correlations', '가능한 연관성')}</h4>
      {boundedItems(result.correlations).map((correlation, index) => <div key={index}><p lang={result.language}>{boundedText(correlation?.interpretation)}</p>{boundedItems(correlation?.issue_ids).map((id, i) => <code key={i}>{boundedText(id)} </code>)}</div>)}
      <h4>{t('Limitations', '한계')}</h4><ul>{boundedItems(result.limitations).map((text, index) => <li lang={result.language} key={index}>{boundedText(text)}</li>)}</ul>
      <p className="muted">{t('Display is bounded to 20 entries per section and 2,000 characters per field; longer content is abbreviated.', '화면에는 섹션당 최대 20개 항목, 필드당 2,000자만 표시하며 긴 내용은 축약됩니다.')}</p>
    </article>}
  </section>;
}
