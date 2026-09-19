import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from './api';
import { useReportLanguage } from './reportLanguageContext';
import { choose } from './reportTranslations';

type Interpretation = {
  schema_version: 'ddos-interpretation-v1'; kind: 'MODEL_INTERPRETATION'; language: 'ko' | 'en';
  summary: string;
  risk_context: { interpretation: string; finding_ids: string[]; uncertainty: string }[];
  prioritized_checks: { priority: string; check: string; finding_ids: string[] }[];
  response_considerations: { consideration: string; finding_ids: string[]; requires_human_approval: true }[];
  limitations: string[];
};
type Run = { id: string; analysis_kind: string; status: string; language: 'ko' | 'en'; progress_percent?: number; error_code?: string; error_message?: string; ddos_interpretation?: Interpretation };
type Capabilities = { ddos_interpretation: boolean; available: boolean; provider: string; model_name: string; destination: string | null; remote: boolean; reason: string | null };
const activeStatuses = new Set(['QUEUED', 'PREPARING', 'ANALYZING', 'VALIDATING']);
const boundedText = (value: unknown) => typeof value === 'string' ? (value.length > 2000 ? `${value.slice(0, 2000)}…` : value) : '';
const bounded = <T,>(value: T[]) => Array.isArray(value) ? value.slice(0, 20) : [];

export default function DDoSAIInterpretation({ jobId, completed }: { jobId: string; completed: boolean }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => choose(language, en, ko);
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const [submitted, setSubmitted] = useState<Run>();
  const [consentedDestination, setConsentedDestination] = useState<string | null>(null);
  const capabilities = useQuery<Capabilities, Error>({ queryKey: ['ai-capabilities'], queryFn: () => api.get('/ai-capabilities'), retry: false });
  const config = capabilities.data;
  const allowRemote = Boolean(config?.remote && config.destination && consentedDestination === config.destination);
  const runs = useQuery<{ items: Run[] }, Error>({ queryKey: ['ai-runs', jobId], queryFn: () => api.get(`/analysis-jobs/${jobId}/ai-runs`), retry: false });
  const saved = runs.data?.items?.find(item => item.analysis_kind === 'DDOS_ATTACK');
  const latest = submitted ?? saved;
  const detail = useQuery<Run, Error>({
    queryKey: ['ai-run', latest?.id], queryFn: () => api.get(`/ai-runs/${latest?.id}`), enabled: Boolean(latest?.id), retry: false,
    refetchInterval: query => activeStatuses.has(query.state.data?.status ?? latest?.status ?? '') ? 2000 : false,
  });
  const current = detail.data ?? latest;
  const active = Boolean(current && activeStatuses.has(current.status));
  const canStart = completed && config?.available === true && config.ddos_interpretation === true
    && (!config.remote || allowRemote) && runs.isSuccess && !active;
  const start = useMutation({
    mutationFn: () => api.post<Run>(`/analysis-jobs/${jobId}/ai-runs`, { idempotency_key: `web-ddos-${jobId}-${Date.now()}`, analysis_kind: 'DDOS_ATTACK', language, allow_remote: allowRemote }),
    onSuccess: async created => { setSubmitted(created); await client.invalidateQueries({ queryKey: ['ai-runs', jobId] }); },
  });
  const cancel = useMutation({
    mutationFn: () => api.post(`/ai-runs/${current?.id}/cancel`, { reason: 'operator requested from web console' }),
    onSuccess: async () => { await client.invalidateQueries({ queryKey: ['ai-run', current?.id] }); },
  });
  const result = current?.status === 'COMPLETED' && current.ddos_interpretation?.schema_version === 'ddos-interpretation-v1'
    && current.ddos_interpretation.kind === 'MODEL_INTERPRETATION'
    ? current.ddos_interpretation : undefined;
  return <section className="panel" aria-labelledby="ai-ddos-heading">
    <h2 id="ai-ddos-heading">{t('DDoS AI interpretation', 'DDoS AI 해석')}</h2>
    <button type="button" className="secondary" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? t('Close DDoS AI interpretation', 'DDoS AI 해석 닫기') : t('Open DDoS AI interpretation', 'DDoS AI 해석 열기')}</button>
    {open && <>
      <p>{t('AI explains the saved deterministic report; it cannot change the verdict, attribute an actor, prove impact, or execute a response.', 'AI는 저장된 결정론적 보고서를 설명할 뿐 판정 변경, 공격자 귀속, 영향 입증, 대응 실행을 할 수 없습니다.')}</p>
      <p className="muted">{t('Manual only. Only a bounded report projection is sent; raw packets and payloads are excluded.', '수동 실행 전용입니다. 제한된 보고서 투영만 전송하며 원시 패킷과 페이로드는 제외합니다.')}</p>
      {config && <p>{config.provider} · {config.model_name} · {config.destination ?? t('Local or not reported', '로컬 또는 보고되지 않음')}</p>}
      {config?.remote && <label className="check"><input type="checkbox" checked={allowRemote} onChange={event => setConsentedDestination(event.target.checked ? config.destination : null)}/>{t('I consent to this remote destination.', '이 원격 대상 전송에 동의합니다.')}</label>}
      <button type="button" disabled={!canStart || start.isPending} onClick={() => start.mutate()}>{start.isPending ? t('Starting…', '시작 중…') : t('Run DDoS AI interpretation', 'DDoS AI 해석 실행')}</button>
    </>}
    {!completed && <p className="muted">{t('A completed DDoS report is required.', '완료된 DDoS 보고서가 필요합니다.')}</p>}
    {(capabilities.isError || runs.isError || detail.isError) && <p role="alert" className="error-text">{t('AI status lookup failed.', 'AI 상태 조회에 실패했습니다.')}</p>}
    {config && (!config.available || !config.ddos_interpretation) && <p role="alert" className="error-text">{t('DDoS AI interpretation is unavailable', 'DDoS AI 해석을 사용할 수 없습니다')}: {config.reason}</p>}
    {start.error && <p role="alert" className="error-text">{boundedText(start.error.message)}</p>}
    {current && <div className="ai-run-summary" role="status"><span className={`badge ${active ? 'medium' : 'low'}`}>{boundedText(current.status)}</span>{typeof current.progress_percent === 'number' && <progress max="100" value={Math.max(0, Math.min(100, current.progress_percent))}/>} {active && <button type="button" className="secondary" disabled={cancel.isPending} onClick={() => cancel.mutate()}>{t('Cancel AI run', 'AI 실행 취소')}</button>}</div>}
    {current?.error_code && <p role="alert" className="error-text">{boundedText(current.error_code)}: {boundedText(current.error_message)}</p>}
    {open && result && <article className="ai-assessment" aria-label={t('Full DDoS AI interpretation', 'DDoS AI 해석 전체 원문')}>
      <h3>{t('AI-generated interpretation — analyst review required', 'AI 생성 해석 — 분석가 검토 필요')}</h3>
      <p lang={result.language}>{boundedText(result.summary)}</p>
      <h4>{t('Risk context', '위험 문맥')}</h4>{bounded(result.risk_context).map((item, index) => <div key={index}><p lang={result.language}>{boundedText(item.interpretation)}</p><p lang={result.language}>{boundedText(item.uncertainty)}</p><code>{bounded(item.finding_ids).join(' ')}</code></div>)}
      <h4>{t('Prioritized checks', '우선 확인 사항')}</h4><ol>{bounded(result.prioritized_checks).map((item, index) => <li key={index}><strong>{boundedText(item.priority)}</strong> <span lang={result.language}>{boundedText(item.check)}</span> <code>{bounded(item.finding_ids).join(' ')}</code></li>)}</ol>
      <h4>{t('Response considerations', '대응 검토 사항')}</h4><ul>{bounded(result.response_considerations).map((item, index) => <li key={index}><span lang={result.language}>{boundedText(item.consideration)}</span> — {t('human approval required', '운영자 승인 필요')} <code>{bounded(item.finding_ids).join(' ')}</code></li>)}</ul>
      <h4>{t('Limitations', '한계')}</h4><ul>{bounded(result.limitations).map((item, index) => <li key={index} lang={result.language}>{boundedText(item)}</li>)}</ul>
    </article>}
  </section>;
}
