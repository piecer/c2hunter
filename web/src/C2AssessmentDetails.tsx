import { useState } from 'react';
import type { DiscoveryOrigin } from './C2DiscoverySelection';
import { useReportLanguage } from './reportLanguageContext';

type AIFactor = { title: string; evidence_ids: string[]; explanation: string; strength?: string };
export type AIAssessment = {
  id: string; candidate_id: string; external_ip: string; review_priority?: number;
  discovery_origin?: DiscoveryOrigin; behavior_anomaly_score?: number | null;
  evidence_bundle?: {
    candidate?: { existing_c2hunter_score?: number; [key: string]: unknown };
    metadata?: { reduced?: boolean };
    evidence?: { id: string; type: string; summary: string; contribution?: number | null; metrics?: Record<string, unknown> }[];
  };
  assessment: {
    candidate: { external_ip: string; verdict: string; confidence: number; summary_ko: string; summary_en: string };
    supporting_factors: AIFactor[]; counter_factors: AIFactor[]; missing_information: string[]; limitations: string[];
    recommended_actions?: { action: string; reason?: string; priority?: string; passive_only?: boolean }[];
  };
};

export default function C2AssessmentDetails({ item }: { item: AIAssessment }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  const [open, setOpen] = useState(false);
  const result = item.assessment;
  const bundle = item.evidence_bundle;
  const evidenceIds = [...new Set([...(result.supporting_factors ?? []), ...(result.counter_factors ?? [])].flatMap(factor => factor.evidence_ids ?? []))];
  return <>
    <section aria-label={t('Observed facts', '관찰된 사실')} className="c2-observed-facts">
      <h4>{t('Observed facts', '관찰된 사실')}</h4>
      <dl><dt>{t('Origin', '출처')}</dt><dd>{item.discovery_origin ?? t('Not reported', '보고되지 않음')}</dd>
        <dt>{t('Source score', '원본 점수')}</dt><dd>{bundle?.candidate?.existing_c2hunter_score ?? '—'}</dd>
        <dt>{t('Behavior anomaly score', '행동 이상 점수')}</dt><dd>{item.behavior_anomaly_score ?? '—'}</dd></dl>
      {bundle?.metadata?.reduced && <p className="warning">{t('Evidence bundle was reduced; missing evidence does not mean absence of activity.', '증거 묶음이 축약되었습니다. 누락된 증거가 활동의 부재를 뜻하지 않습니다.')}</p>}
      <button type="button" className="secondary" aria-expanded={open} onClick={() => setOpen(!open)}>{t('View saved evidence', '저장된 증거 보기')}</button>
      {open && <div className="c2-evidence-details">
        {!bundle && <p>{t('No saved evidence bundle is available for this older assessment.', '이 이전 판정에는 저장된 증거 묶음이 없습니다.')}</p>}
        {bundle?.candidate && <><h5>{t('Candidate snapshot', '후보 스냅샷')}</h5><pre>{JSON.stringify(bundle.candidate, null, 2)}</pre></>}
        {(bundle?.evidence ?? []).map((evidence, index) => <article key={`${evidence.id}-${index}`}>
          <h5><code>{evidence.id}</code> · {evidence.type}</h5><p>{evidence.summary}</p>
          <p>{t('Contribution', '기여도')}: {evidence.contribution ?? '—'}</p>
          {evidence.metrics && <pre>{JSON.stringify(evidence.metrics, null, 2)}</pre>}
        </article>)}
      </div>}
    </section>
    <section aria-label={t('AI interpretation', 'AI 해석')} className="c2-ai-interpretation">
      <h4>{t('AI interpretation — analyst review required', 'AI 해석 — 분석가 검토 필요')}</h4>
      <p className="muted">{t('Model confidence is not a calibrated probability of maliciousness. AI interpretation is not an observed fact or an automatic blocking decision.', '모델 신뢰도는 보정된 악성 확률이 아닙니다. AI 해석은 관찰된 사실이나 자동 차단 결정이 아닙니다.')}</p>
      <p lang={language}>{language === 'ko' ? result.candidate.summary_ko : result.candidate.summary_en}</p>
      {([[t('Supporting evidence', '지지 근거'), result.supporting_factors], [t('Counter evidence', '반대 근거'), result.counter_factors]] as const).map(([heading, factors]) => <div key={heading}>
        <h4>{heading}</h4>{factors?.length ? factors.map((factor, index) => <div className="ai-factor" key={index}><strong>{factor.title}</strong><p>{factor.explanation}</p>{factor.strength && <small>{t('Strength', '강도')}: {factor.strength}</small>}<small>{t('References', '참조')}: {(factor.evidence_ids ?? []).join(', ')}</small></div>) : <p>{t('None reported', '보고된 항목 없음')}</p>}
      </div>)}
      <dl><dt>{t('Evidence IDs', '근거 ID')}</dt><dd>{evidenceIds.length ? evidenceIds.map(id => <code key={id}>{id}</code>) : t('No linked evidence', '연결된 근거 없음')}</dd><dt>{t('Missing information', '누락 정보')}</dt><dd>{result.missing_information?.join(', ') || t('None reported', '보고된 항목 없음')}</dd></dl>
      <h4>{t('Next checks (AI suggestions)', '다음 확인 사항 (AI 제안)')}</h4>
      {result.recommended_actions?.length ? <ul>{result.recommended_actions.map((action, index) => <li key={index}><strong>{action.action}</strong>{action.reason && <p>{action.reason}</p>}<small>{action.priority}{action.passive_only ? t(' · Passive only', ' · 수동 관찰 전용') : ''}</small></li>)}</ul> : <p>{t('None reported', '보고된 항목 없음')}</p>}
      <h4>{t('Limitations', '한계')}</h4><ul>{(result.limitations ?? []).map((limitation, index) => <li key={index}>{limitation}</li>)}</ul>
    </section>
  </>;
}
