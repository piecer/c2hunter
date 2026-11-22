import { useReportLanguage } from './reportLanguageContext';

type Assessment = { status: string; signal: string; configured_providers: number; successful_providers: number; positive_providers: number; misp_event_count: number; virustotal_malicious: number; virustotal_suspicious: number; abuse_confidence_score: number };

/** Same queue TI facts, without nested per-provider layout wrappers. */
export default function CandidateQueueTI({ assessment }: { assessment?: Assessment }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  if (!assessment || assessment.signal === 'UNKNOWN') return <><strong>{t('Not checked', '미조회')}</strong><small>{t('No external TI information', '외부 TI 정보 없음')}</small></>;
  if (assessment.signal === 'NO_SIGNAL') return <><strong>{t('No external signal', '외부 신호 없음')}</strong><small>{assessment.successful_providers}/{assessment.configured_providers} {t('checked · Not a safety verdict', '조회 완료 · 안전 판정 아님')}</small></>;
  return <>
    {assessment.signal === 'INCOMPLETE' && <><strong>{t('Incomplete information', '정보 부족')}</strong>{assessment.status === 'PENDING' ? t('Pending', '조회 중') : assessment.status === 'FAILED' ? t('Failed', '조회 실패') : t('Partial', '부분 완료')}</>}
    {assessment.misp_event_count > 0 && <span>MISP {assessment.misp_event_count}</span>}
    {(assessment.virustotal_malicious > 0 || assessment.virustotal_suspicious > 0) && <span>VT {assessment.virustotal_malicious}/{assessment.virustotal_suspicious}</span>}
    {assessment.abuse_confidence_score > 0 && <span>Abuse {assessment.abuse_confidence_score}%</span>}
    <small>{t(`${assessment.successful_providers}/${assessment.configured_providers} checked · ${assessment.positive_providers} positive`, `${assessment.successful_providers}/${assessment.configured_providers} 조회 · ${assessment.positive_providers}개 양성`)}</small>
  </>;
}
