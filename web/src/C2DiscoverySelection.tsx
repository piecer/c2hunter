import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from './api';
import { historicalAccessDenied, historicalErrorText } from './historicalReferenceErrors';
import { useReportLanguage } from './reportLanguageContext';

export type DiscoveryOrigin = 'RULE' | 'PREFILTER' | 'BEHAVIOR' | 'RULE_AND_BEHAVIOR';
export type SelectionSummary = {
  version: 'behavior-selection-v1'; candidate_pool_count: number; selected_count: number; omitted_count: number;
  discovery_candidate_count: number; discovery_selected_count: number; rule_free_selected_count: number;
  reserved_discovery_slots: number; warnings: string[];
};
type SelectionPage = {
  items: { candidate_id: string; external_ip: string; origin: DiscoveryOrigin; existing_score: number; anomaly_score: number | null; selected: boolean; reason: 'DISCOVERY_RESERVED' | 'RANKED' | 'BUDGET_LIMIT' }[];
  total: number; offset: number; limit: number; next_offset: number | null;
};

// The caller keys this component by run: page history belongs to one snapshot.
export default function C2DiscoverySelection({ runId, summary }: { runId: string; summary: SelectionSummary }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  const [open, setOpen] = useState(false);
  const [offsets, setOffsets] = useState([0]);
  const offset = offsets[offsets.length - 1];
  const page = useQuery<SelectionPage, Error>({
    queryKey: ['ai-selection', runId, offset],
    queryFn: () => api.get(`/ai-runs/${runId}/selection?offset=${offset}&limit=20`),
    enabled: open, retry: false, retryOnMount: false, staleTime: Infinity, refetchOnWindowFocus: false, refetchOnReconnect: false,
  });
  const next = page.data?.next_offset;
  return <section className="c2-discovery" aria-label={t('Discovery coverage', '탐색 범위')}>
    <h3>{t('Shadow discovery coverage', 'Shadow 탐색 범위')}</h3>
    <p>{t(`Candidate pool ${summary.candidate_pool_count} · Selected ${summary.selected_count} · Omitted ${summary.omitted_count}`, `후보 풀 ${summary.candidate_pool_count} · 선택 ${summary.selected_count} · 미선택 ${summary.omitted_count}`)}</p>
    <p>{t(`Discovery candidates ${summary.discovery_candidate_count} · Discovery selected ${summary.discovery_selected_count} · Rule-free selected ${summary.rule_free_selected_count} · Reserved slots ${summary.reserved_discovery_slots}`, `탐색 후보 ${summary.discovery_candidate_count} · 탐색 선택 ${summary.discovery_selected_count} · 규칙 없는 선택 ${summary.rule_free_selected_count} · 예약 슬롯 ${summary.reserved_discovery_slots}`)}</p>
    <p className="warning">{t('This is a budget-limited review, not complete traffic coverage. Omitted does not mean benign.', '예산 제한 검토이며 전체 트래픽을 포괄하지 않습니다. 미선택은 안전하다는 뜻이 아닙니다.')}</p>
    {(summary.warnings ?? []).map((warning, index) => <p className="warning" key={index}><code>{warning}</code></p>)}
    <button type="button" className="secondary" aria-expanded={open} onClick={() => setOpen(!open)}>{t('View selection inventory', '선택 목록 보기')}</button>
    {open && <>
      <p className="muted">{t('Immutable selection snapshot · up to 20 rows per page. Source score and behavior anomaly are separate signals, not malicious probabilities.', '불변 선택 스냅샷 · 페이지당 최대 20행. 원본 점수와 행동 이상 점수는 서로 다른 신호이며 악성 확률이 아닙니다.')}</p>
      {page.isLoading && <p role="status">{t('Loading selection…', '선택 목록 조회 중…')}</p>}
      {page.isError && <p role="alert">{t('Selection could not be read', '선택 목록 조회 실패')}: {historicalAccessDenied(page.error) ? historicalErrorText(page.error, language) : page.error.message} {!historicalAccessDenied(page.error) && <button type="button" onClick={() => void page.refetch()}>{t('Retry selection', '선택 목록 재시도')}</button>}</p>}
      <div className="table-wrap"><table aria-label={t('Selection inventory', '선택 목록')}><thead><tr>
        <th>IP</th><th>{t('Origin', '출처')}</th><th>{t('Source score', '원본 점수')}</th><th>{t('Behavior anomaly score', '행동 이상 점수')}</th><th>{t('Selected', '선택 여부')}</th><th>{t('Reason', '이유')}</th>
      </tr></thead><tbody>{!page.isError && page.data?.items.map(item => <tr key={item.candidate_id}>
        <td>{item.external_ip}</td><td>{item.origin}</td><td>{item.existing_score}</td><td>{item.anomaly_score ?? '—'}</td><td>{item.selected ? t('Selected', '선택') : t('Omitted', '미선택')}</td><td>{item.reason}</td>
      </tr>)}</tbody></table></div>
      <div className="ai-run-controls">
        <button type="button" className="secondary" disabled={offsets.length === 1 || page.isFetching} onClick={() => setOffsets(previous => previous.slice(0, -1))}>{t('Previous selection page', '이전 선택 목록')}</button>
        <span role="status">{page.data && !page.isError ? t(`Offset ${page.data.offset} · ${page.data.items.length} of ${page.data.total} candidates`, `시작 ${page.data.offset} · 전체 ${page.data.total}개 중 ${page.data.items.length}개`) : '—'}</span>
        <button type="button" className="secondary" disabled={page.isFetching || page.isError || next == null || next <= offset} onClick={() => { if (next != null && next > offset) setOffsets(previous => [...previous, next]); }}>{t('Next selection page', '다음 선택 목록')}</button>
      </div>
    </>}
  </section>;
}
