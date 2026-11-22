import InterpretationCancellationReceipts from './InterpretationCancellationReceipts';
import type { ReactNode } from 'react';
import { InterpretationAdmissionContext, useLocalInterpretationAdmission } from './interpretationAdmission';
import { useReportLanguage } from './reportLanguageContext';

// Only effectful AI ownership is above AsyncState; no stale job body is retained.
// Compose alongside the independent IP/job-investigation owners, not around their
// source views. The enclosing route/auth boundary retires this owner.
export default function AppJobDetailOwner({ jobId, sourceError, children }: { jobId: string; sourceError: boolean; children: ReactNode }) {
  const network = useLocalInterpretationAdmission(jobId, 'NETWORK_ANOMALY');
  const ddos = useLocalInterpretationAdmission(jobId, 'DDOS_ATTACK');
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  return <InterpretationAdmissionContext.Provider value={{ NETWORK_ANOMALY: network, DDOS_ATTACK: ddos }}>
    {sourceError && [network, ddos].map((owner, index) => <div key={index}>
      {owner.start.isPending && <p role="status">{t('AI request pending — admission not yet confirmed.', 'AI 요청 대기 중 — 접수는 아직 확인되지 않았습니다.')}</p>}
    {owner.start.isError && <><p>{t('Retry preserves the original language, remote consent and request key.', '재시도는 원래 언어, 원격 동의와 요청 키를 유지합니다.')} {owner.start.variables?.body.language} · {owner.start.variables?.destination?.destination ?? '—'}</p><button type="button" disabled={owner.admissionRecovery === 'pending'} onClick={() => void owner.retryAdmission()}>{t('Retry exact AI request', '동일한 AI 요청 재시도')}</button></>}
    {owner.admissionRecovery === 'blocked' && <p role="status">{t('Original model destination or request receipt could not be confirmed; no new request is authorized.', '원래 모델 대상 또는 요청 응답을 확인하지 못했습니다. 새 요청은 허용되지 않습니다.')}</p>}
      {owner.start.isError && <p role="status">{t('AI admission unconfirmed. Review the request before trying again.', 'AI 접수 미확인. 재시도 전에 요청을 확인하세요.')}</p>}
      <InterpretationCancellationReceipts owner={owner}/>
      {owner.knownRun && <>
        <p role="status">{owner.observed ? owner.observed.status : t('Current AI run status is unconfirmed.', '현재 AI 실행 상태를 확인할 수 없습니다.')}</p>
        <button type="button" disabled={owner.statusQuery.isFetching} onClick={owner.retryStatus}>{t('Retry status lookup', '상태 조회 재시도')}</button>
        {owner.active && <button type="button" disabled={owner.cancellationFor(owner.observed?.id).blocked || owner.cancellationFor(owner.observed?.id).capacity} onClick={() => { if (owner.current() && owner.observed) owner.requestCancellation(owner.observed, owner.current); }}>{t('Cancel AI run', 'AI 실행 취소')}</button>}
      </>}
      {owner.knownRun && <p role="status">{t('Owned AI run retained; current source is unavailable.', 'AI 실행 소유권 보존 중 — 현재 원본을 사용할 수 없습니다.')} {owner.knownRun.id}</p>}
    </div>)}
    {children}
  </InterpretationAdmissionContext.Provider>;
}
