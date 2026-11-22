import type { useLocalInterpretationAdmission } from './interpretationAdmission';
import { useReportLanguage } from './reportLanguageContext';

export default function InterpretationCancellationReceipts({ owner }: { owner: ReturnType<typeof useLocalInterpretationAdmission> }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  return <>{owner.cancellationFor(owner.knownRun?.id).capacity && <p role="status">{t('Cancellation receipt capacity reached (4). Reconcile and dismiss a retained receipt before cancelling another run.', '취소 응답 기록 한도(4)에 도달했습니다. 다른 실행을 취소하려면 보존된 기록을 확인하고 닫으세요.')}</p>}{owner.cancellationReceipts.map(held => <div role="group" aria-label={`${t('Cancellation receipt', '취소 응답 기록')} ${held.run.id}`} key={held.run.id} style={{ overflowWrap: 'anywhere' }}>
    <p>{t('Cancellation run', '취소 실행')}: {held.run.id} · {held.run.language}</p>
    {held.state === 'pending' && <p role="status">{t('AI cancellation pending — stopping is not yet confirmed.', 'AI 취소 대기 중 — 중지는 아직 확인되지 않았습니다.')}</p>}
    {held.state === 'unconfirmed' && <><p role="status">{t('AI cancellation unconfirmed — the run may still be active.', 'AI 취소 미확인 — 실행이 계속 진행 중일 수 있습니다.')}</p><button type="button" disabled={held.reconciliation === 'pending'} onClick={() => void owner.reconcileCancellation(held)}>{t('Reconcile cancellation status', '취소 상태 확인')}</button></>}
    {held.reconciliation === 'unknown' && <p role="status">{t('Matching run status remains unknown.', '해당 실행 상태는 아직 알 수 없습니다.')}</p>}
    {held.reconciliation === 'terminal-unacknowledged' && <p role="status">{t('Terminal status observed; original cancellation acknowledgement remains unknown. Worker release is not confirmed.', '종료 상태 관찰됨. 원래 취소 응답과 작업자 해제는 확인되지 않았습니다.')}</p>}
    {held.reconciliation === 'active' && <p role="status">{t('Matching run is still active; worker release is not confirmed.', '해당 실행이 아직 진행 중입니다. 작업자 해제는 확인되지 않았습니다.')}</p>}
    {(held.state === 'acknowledged' || held.reconciliation === 'terminal') && <p role="status">{t('Matching cancellation response received; worker release is not confirmed.', '해당 취소 응답을 받았습니다. 작업자 해제는 확인되지 않았습니다.')}</p>}
    {['acknowledged', 'reconciled'].includes(held.state) && <button type="button" onClick={() => owner.dismissCancellation(held)}>{t('Dismiss cancellation receipt', '취소 응답 기록 닫기')}</button>}
  </div> )}</>;
}
