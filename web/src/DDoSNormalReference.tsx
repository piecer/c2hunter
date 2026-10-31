import { useEffect, useId, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from './api';
import ReportLanguageScope from './ReportLanguage';
import { useReportLanguage } from './reportLanguageContext';

type Entry = { id: string; dataset_id?: string; name: string; status: string };
type Page = { items: Entry[]; total: number; page: number; page_size: number };
type Props = { inherit?: boolean; datasetId?: string; disabled?: boolean };
function Picker({ inherit, datasetId, disabled }: Props) {
  const language = useReportLanguage();
  const queryOwner = useId();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  const [mode, setMode] = useState(inherit ? 'inherit' : 'clear');
  const [page, setPage] = useState(1);
  const [selection, setSelection] = useState<Entry>();
  const action = useRef<HTMLSelectElement>(null);
  useEffect(() => { action.current?.setCustomValidity(mode === 'select' && !selection ? (language === 'ko' ? '제출 전 정상 데이터셋을 선택하세요.' : 'Select a normal dataset before submitting.') : ''); }, [mode, selection, language]);
  const jobs = useQuery<Page, Error>({
    queryKey: ['ddos-normal-reference', queryOwner, datasetId, page],
    queryFn: () => api.get(`/analysis-jobs?page=${page}&page_size=20&status=COMPLETED&sort=-created_at`),
    enabled: mode === 'select', retry: false,
  });
  return <fieldset className="ddos-normal-reference" disabled={disabled}><legend>{t('Independent normal reference', '독립적인 정상 참조')}</legend>
    <label>{t('Normal reference action', '정상 참조 작업')}<select ref={action} name="ddos_reference_mode" value={mode} onChange={event => { setMode(event.target.value); setSelection(undefined); }}>
      {inherit && <option value="inherit">{t('Keep frozen reference (no source lookup)', '고정된 참조 유지 (원본 재조회 없음)')}</option>}
      <option value="clear">{t('No normal reference / clear', '정상 참조 없음 / 해제')}</option>
      <option value="select">{t('Select a different normal dataset', '다른 정상 데이터셋 선택')}</option>
    </select></label>
    <p>{t('Selection is your explicit assertion of normality, not an automatic recommendation. The server validates eligibility, the 512-record / 1 MiB source limit and 256 KiB projection; public summaries cannot prove these bounds.', '선택은 운영자의 명시적인 정상성 판단이며 자동 추천이 아닙니다. 서버가 적격성, 원본 512개 레코드 / 1 MiB 및 투영 256 KiB 제한을 검증합니다. 공개 요약만으로 이 제한을 확인할 수 없습니다.')}</p>
    <p>{t('The statistical baseline uses same-capture low-traffic buckets, not known-normal traffic. This separate operator-selected reference is used for candidate predicate evaluation; selecting it does not upgrade flood likelihood or establish normality.', '통계 기준선은 정상으로 확인된 트래픽이 아니라 같은 캡처의 저트래픽 버킷을 사용합니다. 이와 별도로 운영자가 선택한 참조는 후보 조건식 평가용입니다. 이를 선택해도 플러드 가능성을 상향하지 않으며 정상성을 입증하지도 않습니다.')}</p>
    {mode === 'inherit' && <p>{t('Reuses the stored immutable reference even if its original job has been deleted.', '원본 작업이 삭제되어도 저장된 불변 참조를 재사용합니다.')}</p>}
    {mode === 'clear' && <p>{t('False positives remain unmeasured, not zero.', '오탐은 0이 아니라 미측정입니다.')}</p>}
    {mode === 'select' && <>
      {jobs.isFetching && <p role="status">{t('Loading reference page…', '참조 페이지 로딩 중…')}</p>}
      {jobs.isError && <p role="alert">{t('Reference list unavailable:', '참조 목록 사용 불가:')} {jobs.error.message}</p>}
      {!jobs.isFetching && !jobs.isError && jobs.data && <>
        {!jobs.data.items.length && <p>{t('No completed jobs on this page.', '이 페이지에 완료된 작업이 없습니다.')}</p>}
        {jobs.data.items.slice(0, 20).map(job => <label className="ddos-reference-entry" key={job.id}>
          <input type="radio" name="ddos_reference_choice" checked={selection?.id === job.id} disabled={!job.dataset_id || job.dataset_id === datasetId || job.status !== 'COMPLETED'} onChange={() => setSelection(job)}/>
          <span>{t('I assert this dataset is normal:', '이 데이터셋이 정상이라고 판단합니다:')} {job.name}<code>{job.id}</code><code>{job.dataset_id ?? t('Dataset unavailable', '데이터셋 없음')}</code></span>
        </label>)}
        <nav aria-label={t('Normal reference pages', '정상 참조 페이지')}><button type="button" className="secondary" disabled={page === 1} onClick={() => setPage(page - 1)}>{t('Previous reference page', '이전 참조 페이지')}</button><span>{page}</span><button type="button" className="secondary" disabled={page * 20 >= jobs.data.total} onClick={() => setPage(page + 1)}>{t('Next reference page', '다음 참조 페이지')}</button></nav>
      </>}
      {selection && <p>{t('Selected job / dataset:', '선택한 작업 / 데이터셋:')} <code>{selection.id}</code> / <code>{selection.dataset_id}</code></p>}
      <input type="hidden" name="ddos_reference_job" value={selection?.id ?? ''}/><input type="hidden" name="ddos_reference_dataset" value={selection?.dataset_id ?? ''}/>
    </>}
  </fieldset>;
}
export default function DDoSNormalReference(props: Props) {
  return <ReportLanguageScope><Picker {...props}/></ReportLanguageScope>;
}
