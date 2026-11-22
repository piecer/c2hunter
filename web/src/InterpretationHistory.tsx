import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from './api';
import { interpretationPage } from './interpretationRuns';
import { useReportLanguage } from './reportLanguageContext';

export type SavedInterpretationRun = { id: string; analysis_kind: string; status: string; language: 'ko' | 'en'; created_at?: string };
export type InterpretationRunPage = { items: SavedInterpretationRun[]; current_page?: number; page_size?: number; total?: number };
export default function InterpretationHistory({ first, jobId, kind, selectedId, select }: { first?: InterpretationRunPage; jobId: string; kind: string; selectedId?: string; select: (id?: string) => void }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  const [page, setPage] = useState(1);
  const [offset, setOffset] = useState(0);
  // History paging never writes to the newest-run controller's query namespace.
  const history = useQuery<InterpretationRunPage, Error>({ queryKey: ['interpretation-history', jobId, page], queryFn: () => api.get(`/analysis-jobs/${encodeURIComponent(jobId)}/ai-runs?page=${page}&page_size=50`), enabled: page > 1, retry: false, gcTime: 0 });
  const raw = page === 1 ? first : history.data;
  const data = raw ? interpretationPage(raw, page) : undefined;
  const items = Array.isArray(data?.items) ? data.items.filter(item => item.analysis_kind === kind) : [];
  // Historical navigation also supports the legacy page spelling and sparse
  // pages. These bounds authorize only a manual GET, never admission discovery.
  const meta = raw as (InterpretationRunPage & { page?: number }) | undefined;
  const historyPage = meta?.current_page ?? meta?.page;
  const size = meta?.page_size, total = meta?.total;
  const more = historyPage === page && Number.isSafeInteger(size) && size! >= 1 && size! <= 200 && Number.isSafeInteger(total) && total! >= 0 && page * size! < total!;
  const busy = page > 1 && history.isFetching;
  return <section aria-label={t('Saved AI runs', '저장된 AI 실행')} style={{ overflowWrap: 'anywhere' }}>
    <h3>{t('Saved AI runs', '저장된 AI 실행')}</h3>
    <button type="button" className="secondary" onClick={() => select(undefined)}>{t('Follow latest run', '최신 실행 보기')}</button>
    {history.isError && page > 1 && <><p role="alert">{t('Saved history could not be read.', '저장 이력을 읽지 못했습니다.')}</p><button type="button" onClick={() => void history.refetch()}>{t('Retry history lookup', '이력 조회 재시도')}</button></>}
    {busy && <p role="status">{t('Loading saved AI runs…', '저장된 AI 실행 조회 중…')}</p>}
    {data && !items.length && <p>{t('No matching runs on this page.', '이 페이지에 해당 실행이 없습니다.')}</p>}
    <ul>{items.slice(offset, offset + 5).map(item => <li key={item.id}><button type="button" className="secondary" aria-pressed={selectedId === item.id} onClick={() => select(item.id)}>{t('View saved run', '저장 실행 보기')} {item.id}</button> · {typeof item.created_at === 'string' ? item.created_at.slice(0, 2000) : '—'} · {item.language === 'ko' ? '한국어' : item.language === 'en' ? 'English' : t('Requested language not reported', '요청 언어 보고되지 않음')}</li>)}</ul>
    <nav aria-label={t('Saved run pages', '저장 실행 페이지')}>
      <button type="button" className="secondary" disabled={busy || (page === 1 && offset === 0)} onClick={() => { if (offset > 0) setOffset(Math.max(0, offset - 5)); else { setPage(page - 1); setOffset(0); } }}>{t('Previous saved runs', '이전 저장 실행')}</button>
      <span>{t('History page', '이력 페이지')} {page} · {t('Matching runs on page', '페이지 내 해당 실행')} {items.length}</span>
      <button type="button" className="secondary" disabled={busy || !(offset + 5 < items.length || more)} onClick={() => { if (offset + 5 < items.length) setOffset(offset + 5); else { setPage(page + 1); setOffset(0); } }}>{t('Next saved runs', '다음 저장 실행')}</button>
    </nav>
  </section>;
}
