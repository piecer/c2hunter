import { Fragment, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from './api';
import { historicalErrorText } from './historicalReferenceErrors';
import { historicalReasons } from './historicalReferenceReasons';
import { useReportLanguage } from './reportLanguageContext';

type Status = 'READY' | 'INSUFFICIENT' | 'STALE' | 'MISSING' | 'INCOMPATIBLE';
export type BaselineSummary = {
  mode: 'historical'; schema_version: 'historical-baseline-v1'; scope_id: string;
  scope_kind: 'OPERATIONAL' | 'EVALUATION'; scope_config_sha256: string; scope_revision: number;
  scope_state: string; frozen_at_admission: boolean; generation_id: string | null; generation_sha256: string | null;
  target_event_start: string; target_event_end: string; target_source_binding_sha256: string; admitted_at: string;
  comparison_semantics: string; identity_assurance: string; quality_assurance: 'ANALYST_ASSERTED' | 'UNREVIEWED';
  producer_completeness: 'UNKNOWN'; profile_counts: Record<Status, number>;
  unprofiled_count: number; historical_candidate_count: number; warnings: string[];
};
type Feature = {
  status: Status; current: number | null; reference_median: number | null; reference_scale: number | null;
  robust_z: number | null; eligible_window_ids: string[]; excluded_future_count: number; drifting: boolean;
};
type Comparison = {
  key: { scope_config_sha256: string; sensor_key: string; internal_host_ip: string; host_epoch: string; peer_ip: string; protocol: string; service_port: number; observation_kind: string; feature_version: string };
  status: Status; limitations: string[]; source_window_ids: string[]; historical_anomaly_score: number; selected: boolean;
  features: { recurrence: Feature; size_dispersion: Feature; outbound_share: Feature };
};
type Source = {
  source_receipt_id: string; source_job_id: string; root_job_id: string; dataset_id: string; root_identity: string;
  ancestry_job_ids: string[]; root_content_sha256: string | null; source_binding_sha256: string;
  observation_sha256: string; feature_observation_sha256: string; actual_sensor_id: string; sensor_key: string;
  event_start: string; event_end: string; origin: string; origin_assurance: string; normality: string;
  approved_by: string; approved_at: string; reason: string; producer_completeness: string; known_partial: boolean; limitations: string[];
  quality_review: { representative_window_asserted: boolean; stable_host_attribution_asserted: boolean; clock_offset_bound_ms: number; sensor_alias_asserted: boolean; note: string };
};
type SavedPage<T> = { items: T[]; total: number; offset: number; limit: number; next_offset: number | null };
type Tab = 'comparisons' | 'sources';

function Fields({ rows }: { rows: [string, string | number | null][] }) {
  return <dl>{rows.map(([label, value]) => <Fragment key={label}><dt>{label}</dt><dd className="hash-value">{value ?? '—'}</dd></Fragment>)}</dl>;
}
function Reasons({ values }: { values: string[] }) {
  const language = useReportLanguage();
  if (values.some(code => !Object.hasOwn(historicalReasons, code))) return <p role="alert">{language === 'ko' ? '지원하지 않는 참조 경고입니다. 범위를 확인할 수 없습니다.' : 'Unsupported reference warning. Coverage cannot be confirmed.'}</p>;
  return <ul className="warning">{values.map(code => <li key={code}>{historicalReasons[code][language === 'ko' ? 1 : 0]} · <code>{code}</code></li>)}</ul>;
}
function ComparisonDetails({ item }: { item: Comparison }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  return <section aria-label={t('Comparison evidence', '비교 증거')}>
    <Fields rows={[[t('Scope configuration SHA-256', '범위 구성 SHA-256'), item.key.scope_config_sha256], [t('Sensor key', '센서 키'), item.key.sensor_key], [t('Host epoch', '호스트 세대'), item.key.host_epoch], [t('Observation kind', '관측 종류'), item.key.observation_kind], [t('Feature version', '특성 버전'), item.key.feature_version]]}/>
    <p>{t('Source windows', '원본 관측 구간')}: {item.source_window_ids.length ? item.source_window_ids.join(' · ') : '—'}</p>
    <Reasons values={item.limitations}/>
    {(['recurrence', 'size_dispersion', 'outbound_share'] as const).map(name => {
      const feature = item.features[name];
      return <section key={name}><h5>{name}</h5><Fields rows={[
        [t('Status', '상태'), feature.status], [t('Current value', '현재 값'), feature.current],
        [t('Reference median', '참조 중앙값'), feature.reference_median], [t('Reference scale', '참조 척도'), feature.reference_scale],
        [t('Robust z', '강건 z'), feature.robust_z], [t('Drifting', '변화 감지'), feature.drifting ? t('Yes', '예') : t('No', '아니요')],
        [t('Excluded future windows', '제외된 미래 관측 구간'), feature.excluded_future_count],
        [t('Eligible window IDs', '적격 관측 구간 ID'), feature.eligible_window_ids.join(' · ') || null],
      ]}/></section>;
    })}
  </section>;
}
function SourceDetails({ item }: { item: Source }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  return <section aria-label={t('Source provenance', '원본 출처')}><Fields rows={[
    [t('Source job ID', '원본 작업 ID'), item.source_job_id], [t('Root job ID', '최상위 작업 ID'), item.root_job_id],
    [t('Dataset ID', '데이터셋 ID'), item.dataset_id], [t('Root identity', '최상위 식별 정보'), item.root_identity],
    [t('Ancestry job IDs', '상위 작업 ID'), item.ancestry_job_ids.join(' · ')],
    [t('Root content SHA-256', '최상위 내용 SHA-256'), item.root_content_sha256],
    [t('Source binding SHA-256', '원본 연결 SHA-256'), item.source_binding_sha256],
    [t('Observation SHA-256', '관측 SHA-256'), item.observation_sha256],
    [t('Feature observation SHA-256', '특성 관측 SHA-256'), item.feature_observation_sha256],
    [t('Actual sensor ID', '실제 센서 ID'), item.actual_sensor_id], [t('Sensor key', '센서 키'), item.sensor_key],
    [t('Origin', '출처'), item.origin], [t('Origin assurance', '출처 보증'), item.origin_assurance],
    [t('Normality recorded by administrator', '관리자가 기록한 정상성'), item.normality],
    [t('Approved by', '승인자'), item.approved_by], [t('Approved at', '승인 시각'), item.approved_at],
    [t('Recorded reason', '기록된 사유'), item.reason], [t('Producer completeness', '생산자 완전성'), item.producer_completeness],
    [t('Known partial', '부분 캡처 확인'), item.known_partial ? t('Yes', '예') : t('No', '아니요')],
    [t('Representative window asserted', '대표 관측 구간 주장'), String(item.quality_review.representative_window_asserted)],
    [t('Stable host attribution asserted', '안정적인 호스트 귀속 주장'), String(item.quality_review.stable_host_attribution_asserted)],
    [t('Asserted clock bound (ms)', '주장된 시계 오차 한계 (ms)'), item.quality_review.clock_offset_bound_ms],
    [t('Sensor alias asserted', '센서 별칭 주장'), String(item.quality_review.sensor_alias_asserted)],
    [t('Recorded quality note', '기록된 품질 검토 메모'), item.quality_review.note],
  ]}/><Reasons values={item.limitations}/></section>;
}

// One page and one expanded record are mounted at a time; no hidden full inventories.
function ReferencePage({ runId, tab }: { runId: string; tab: Tab }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  const [expanded, setExpanded] = useState<number | null>(null);
  const [offsets, setOffsets] = useState([0]);
  const offset = offsets[offsets.length - 1];
  const page = useQuery<SavedPage<Comparison | Source>, Error>({
    queryKey: ['historical-reference-page', runId, tab, offset],
    queryFn: () => api.get(`/ai-runs/${runId}/baseline-${tab}?offset=${offset}&limit=20`),
    retry: false, retryOnMount: false, staleTime: Infinity, refetchOnWindowFocus: false, refetchOnReconnect: false,
  });
  if (page.isLoading) return <p role="status">{t('Loading saved reference…', '저장된 참조 조회 중…')}</p>;
  if (page.error) return <p role="alert">{historicalErrorText(page.error, language)}</p>;
  if (!page.data) return null;
  const next = page.data.next_offset;
  return <>
    <p>{t(`${page.data.items.length} of ${page.data.total} records · up to 20 per page`, `전체 ${page.data.total}개 중 ${page.data.items.length}개 · 페이지당 최대 20개`)}</p>
    <div className="table-wrap"><table aria-label={tab === 'comparisons' ? t('Historical comparisons', '과거 비교 결과') : t('Historical sources', '과거 참조 원본')}>
      <thead><tr>{(tab === 'comparisons' ? [t('Host', '호스트'), 'Peer IP', t('Service', '서비스'), t('Status', '상태'), t('Historical anomaly score', '과거 대비 이상 점수'), t('Selected for AI', 'AI 선택 여부'), t('Details', '상세')] : [t('Receipt ID', '접수 ID'), t('Source job', '원본 작업'), t('Event interval', '관측 구간'), t('Details', '상세')]).map(label => <th key={label}>{label}</th>)}</tr></thead>
      <tbody>{page.data.items.map((row, index) => {
        const comparison = tab === 'comparisons' ? row as Comparison : null;
        const source = tab === 'sources' ? row as Source : null;
        return <Fragment key={index}><tr>{comparison ? <><td>{comparison.key.internal_host_ip}</td><td>{comparison.key.peer_ip}</td><td>{comparison.key.protocol}:{comparison.key.service_port}</td><td>{comparison.status}</td><td>{comparison.historical_anomaly_score}</td><td>{comparison.selected ? t('Selected', '선택') : t('Omitted', '미선택')}</td></> : source && <><td className="hash-value">{source.source_receipt_id}</td><td className="hash-value">{source.source_job_id}</td><td>{source.event_start} – {source.event_end}</td></>}
          <td><button type="button" className="secondary" aria-expanded={expanded === index} onClick={() => setExpanded(expanded === index ? null : index)}>{comparison ? t(`Comparison details ${index + 1}`, `비교 상세 ${index + 1}`) : t(`Source details ${index + 1}`, `원본 상세 ${index + 1}`)}</button></td></tr>
          {expanded === index && <tr><td colSpan={comparison ? 7 : 4}>{comparison ? <ComparisonDetails item={comparison}/> : source && <SourceDetails item={source}/>}</td></tr>}
        </Fragment>;
      })}</tbody>
    </table></div>
    <div className="ai-run-controls">
      <button type="button" className="secondary" disabled={offsets.length === 1 || page.isFetching} onClick={() => { setExpanded(null); setOffsets(previous => previous.slice(0, -1)); }}>{t('Previous reference page', '이전 참조 페이지')}</button>
      <span role="status">{t('Offset', '시작 위치')} {page.data.offset} · {t('Total', '전체')} {page.data.total}</span>
      <button type="button" className="secondary" disabled={page.isFetching || next == null || next <= offset} onClick={() => { if (next != null && next > offset) { setExpanded(null); setOffsets(previous => [...previous, next]); } }}>{t('Next reference page', '다음 참조 페이지')}</button>
    </div>
  </>;
}

export default function HistoricalReferenceDetails({ runId, summary }: { runId: string; summary: BaselineSummary }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  const [inspect, setInspect] = useState(false);
  const [tab, setTab] = useState<Tab | null>(null);
  return <section className="c2-discovery" aria-label={t('Saved historical reference', '저장된 과거 참조')}>
    <h3>{t('Saved historical reference', '저장된 과거 참조')}</h3>
    <p className="warning">{t('Deterministic comparison, not an AI verdict. Matching history is not proof of benign traffic. This saved reference is retrospective, not necessarily known at event time.', '결정론적 비교이며 AI 판정이 아닙니다. 과거와 일치해도 안전한 트래픽의 증명이 아닙니다. 저장된 참조는 사후 비교용이며 관측 당시 알려진 참조라는 뜻이 아닙니다.')}</p>
    <Fields rows={[[t('Scope ID', '범위 ID'), summary.scope_id], [t('Revision', '리비전'), summary.scope_revision], [t('Generation', '세대'), summary.generation_id ?? t('None (null)', '없음 (null)')]]}/>
    <p>{summary.scope_kind} · {summary.scope_state} · {t('Target quality', '대상 품질')}: {summary.quality_assurance} · {t('Completeness', '완전성')}: {summary.producer_completeness}</p>
    <p>{(['READY', 'INSUFFICIENT', 'STALE', 'MISSING', 'INCOMPATIBLE'] as const).map(status => `${status} ${summary.profile_counts[status]}`).join(' · ')}</p>
    <p>{t(`Unprofiled ${summary.unprofiled_count} · Historical candidates ${summary.historical_candidate_count}`, `프로필 없음 ${summary.unprofiled_count} · 과거 대비 후보 ${summary.historical_candidate_count}`)}</p>
    <Reasons values={summary.warnings}/>
    <button type="button" className="secondary" aria-expanded={inspect} onClick={() => setInspect(!inspect)}>{t('Inspect frozen reference', '고정 참조 상세 보기')}</button>
    {inspect && <Fields rows={[
      [t('Scope configuration SHA-256', '범위 구성 SHA-256'), summary.scope_config_sha256], [t('Generation SHA-256', '세대 SHA-256'), summary.generation_sha256],
      [t('Target source binding SHA-256', '대상 원본 연결 SHA-256'), summary.target_source_binding_sha256],
      [t('Target event start', '대상 관측 시작'), summary.target_event_start], [t('Target event end', '대상 관측 종료'), summary.target_event_end],
      [t('Admitted at', '실행 수락 시각'), summary.admitted_at], [t('Comparison semantics', '비교 의미'), summary.comparison_semantics],
      [t('Identity assurance', '식별 보증'), summary.identity_assurance], [t('Scope frozen at admission', '수락 시 범위 동결 여부'), summary.frozen_at_admission ? t('Yes', '예') : t('No', '아니요')],
    ]}/>}
    <div className="row-actions">{(['comparisons', 'sources'] as const).map(value => <button type="button" className="secondary" key={value} aria-expanded={tab === value} onClick={() => setTab(tab === value ? null : value)}>{value === 'comparisons' ? t('View comparisons', '비교 결과 보기') : t('View sources', '원본 목록 보기')}</button>)}</div>
    {tab && <ReferencePage key={`${runId}:${tab}`} runId={runId} tab={tab}/>}
  </section>;
}
