import { useState } from 'react';

type Evidence = { type: string; warnings?: unknown };
const labels: Record<string, [string, string]> = {
  no_response_is_not_host_unavailable: ['No response does not establish that the host is unavailable.', '응답 미관측은 호스트 사용 불가를 입증하지 않습니다.'],
  capture_loss_or_asymmetry_possible: ['Capture loss or asymmetric visibility may hide responses.', '캡처 손실이나 비대칭 관측으로 응답이 보이지 않을 수 있습니다.'],
  response_correlation_truncated: ['Response correlation reached its retention limit; completion may be unobserved.', '응답 상관 분석의 보존 한도에 도달하여 연결 완료를 놓쳤을 수 있습니다.'],
};

/** Summarize the complete evidence set; page disclosures, never truncate warnings. */
export default function CandidateQueueWarnings({ evidence, language }: { evidence: Evidence[]; language: 'en' | 'ko' }) {
  const [expanded, setExpanded] = useState(false);
  const [page, setPage] = useState(0);
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  const warnings = evidence.flatMap((item, index) => Array.isArray(item.warnings)
    ? item.warnings.map((code: unknown) => ({ source: index + 1, type: item.type, code: typeof code === 'string' ? code : null }))
    : item.warnings === undefined ? [] : [{ source: index + 1, type: item.type, code: null }]);
  if (!warnings.length) return null;
  const known = Object.keys(labels).filter(code => warnings.some(item => item.code === code));
  const unknown = warnings.some(item => !item.code || !Object.hasOwn(labels, item.code));
  const size = 10;
  const currentPage = Math.min(page, Math.ceil(warnings.length / size) - 1);
  return <section aria-label={t('Evidence limitations', '근거 관측 한계')}>
    <h4>{t('Evidence limitations', '근거 관측 한계')}</h4>
    {known.map(code => <p key={code}>{labels[code][language === 'ko' ? 1 : 0]}</p>)}
    {unknown && <p>{t('Additional source warnings are reported; coverage remains qualified or unconfirmed. Inspect every warning below.', '추가 출처 경고가 있습니다. 관측 범위에 제한이 있거나 확인되지 않았습니다. 아래에서 모든 경고를 확인하세요.')}</p>}
    <button type="button" aria-expanded={expanded} onClick={() => { setExpanded(!expanded); setPage(0); }}>{expanded ? t('Hide evidence warnings', '근거 경고 숨기기') : t('Show all evidence warnings', '모든 근거 경고 보기')}</button>
    {expanded && <div>
      <p role="status">{t('Warnings', '경고')} {currentPage * size + 1}–{Math.min((currentPage + 1) * size, warnings.length)} / {warnings.length}</p>
      <ul>{warnings.slice(currentPage * size, (currentPage + 1) * size).map((item, index) => <li key={`${currentPage}-${index}`}>
        <span>{t('Evidence', '근거')} {item.source} · {item.type}</span>{' '}<code>{item.code ?? t('Warning details unconfirmed', '경고 세부 정보 확인 불가')}</code>
      </li>)}</ul>
      <button type="button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>{t('Previous warnings', '이전 경고')}</button>
      <button type="button" disabled={(currentPage + 1) * size >= warnings.length} onClick={() => setPage(currentPage + 1)}>{t('Next warnings', '다음 경고')}</button>
    </div>}
  </section>;
}
