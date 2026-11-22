import { useLayoutEffect, useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api, ApiError } from './api';
import { captureAuthentication, currentAuthentication } from './authentication';
import { retireCandidateSource } from './candidateDetailHistory';
import CandidateQueueWarnings from './CandidateQueueWarnings';
import './CandidateQueuePreview.css';

type Preview = { id: string; candidate_ip: string; score: number; severity: string; workflow_status?: string; evidence?: Array<{ type: string; description?: string; warnings?: unknown }> };

/** Readonly projection. Never mount CandidateDetail or its operation controllers here.
 * The scoped detail endpoint verifies job membership server-side (not page membership).
 */
export default function CandidateQueuePreview({ id, jobId, language = 'en', onOpenFull }: { id: string; jobId?: string; language?: 'en' | 'ko'; onOpenFull?: () => void }) {
  const authority = captureAuthentication();
  const client = useQueryClient();
  // Cached data does not revive a retired selection's callbacks.
  const lifetime = useMemo(() => ({ active: false, epoch: authority.epoch, jobId, id, client }), [authority.epoch, jobId, id, client]);
  useLayoutEffect(() => { lifetime.active = true; return () => { lifetime.active = false; }; }, [lifetime]);
  const current = (signal?: AbortSignal) => lifetime.active && currentAuthentication(authority, signal);
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  const query = useQuery({
    queryKey: ['candidate-queue-preview', authority.epoch, jobId ?? null, id],
    queryFn: async ({ signal }) => {
      if (!current(signal)) throw new Error('Retired preview request');
      const path = jobId === undefined ? `/candidates/${encodeURIComponent(id)}` : `/analysis-jobs/${encodeURIComponent(jobId)}/candidates/${encodeURIComponent(id)}`;
      let data: Preview;
      try {
        data = await api.boundedRequest(path, { signal }) as Preview;
      } catch (error) {
        // Error bodies are asynchronous too. A retired preview must never revoke
        // a successor's source. Scoped 404 also means wrong job membership, not
        // global deletion; only the global endpoint's exact contract proves it.
        if (!current(signal)) throw new Error('Retired preview request');
        if (jobId === undefined && error instanceof ApiError && error.status === 404 && error.code === 'CANDIDATE_NOT_FOUND') retireCandidateSource(lifetime.client, authority.epoch, id, error);
        throw error;
      }
      if (!current(signal)) throw new Error('Retired preview request');
      if (!data || data.id !== id || typeof data.candidate_ip !== 'string' || typeof data.score !== 'number' || typeof data.severity !== 'string') throw new Error('Invalid candidate preview');
      return data;
    },
    retry: false,
    staleTime: 0,
  });
  if (!currentAuthentication(authority)) return null;
  if (query.isFetching || query.isPending) return <p role="status">{t('Loading selected candidate…', '선택한 후보 조회 중…')}</p>;
  if (query.isError) {
    const unavailable = query.error instanceof ApiError && [403, 404, 410].includes(query.error.status);
    return <div><p role="alert">{unavailable ? t('Selected candidate unavailable in this scope. It may be removed or access denied. Close to clear the selection.', '이 범위에서 선택한 후보를 사용할 수 없습니다. 삭제되었거나 접근이 거부되었을 수 있습니다. 닫으면 선택을 해제합니다.') : t('Candidate preview could not be refreshed. Coverage is unconfirmed; retry or close this preview.', '후보 미리보기를 갱신하지 못했습니다. 범위를 확인할 수 없습니다. 다시 시도하거나 닫으세요.')}</p><button type="button" onClick={() => { if (current()) void query.refetch(); }}>{t('Retry candidate preview', '후보 미리보기 재시도')}</button></div>;
  }
  const candidate = query.data;
  const evidence = Array.isArray(candidate.evidence) ? candidate.evidence : [];
  return <article data-candidate-preview={id}>
    <h3>{candidate.candidate_ip}</h3><p className="record-id">{candidate.id}</p>
    <p>{t('Detection result', '탐지 결과')}: <strong>{candidate.score} · {candidate.severity}</strong></p>
    <p>{t('Analyst workflow', '분석가 처리 상태')}: {candidate.workflow_status ?? t('Not reported', '기록 없음')}</p>
    <h4>{t('Representative reasons', '대표 근거')}</h4>
    {evidence.length ? <ul>{evidence.slice(0, 3).map((item, index) => <li key={index}>{item.description || item.type}</li>)}</ul> : <p>{t('No retained reasons reported.', '보존된 근거 기록 없음.')}</p>}
    <CandidateQueueWarnings key={`${jobId ?? ''}:${id}`} evidence={evidence} language={language}/>
    <p>{t('Retained candidate evidence only, not a safety verdict for all traffic. AI execution and analyst decisions are separate. This preview shows at most three reasons; all retained evidence is available in the full investigation.', '보존된 후보 근거이며 전체 트래픽의 안전 판정이 아닙니다. AI 실행과 분석가 판정은 별개입니다. 대표 근거는 최대 3개이며 전체 조사에서 모든 보존 근거를 확인할 수 있습니다.')}</p>
    <p>{t('Next check: inspect all evidence, coverage and analyst workflow before deciding.', '다음 확인: 판단 전에 전체 근거, 관측 범위와 처리 상태를 확인하세요.')}</p>
    <Link onClick={onOpenFull} to={`/candidates/${encodeURIComponent(candidate.id)}`}>{t('Open full investigation', '전체 조사 열기')}</Link>
  </article>;
}
