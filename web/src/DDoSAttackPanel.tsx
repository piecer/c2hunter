import { type ReactNode, useEffect, useRef, useState } from 'react';
import { type ExportJob } from './ddosExport';
import DDoSCandidateInspection from './DDoSCandidateInspection';
import ReportLanguageScope from './ReportLanguage';
import { axisNames, axisReasons } from './ddosEvidence';
import { useReportLanguage } from './reportLanguageContext';
import {
  attackTypes, choose, classificationConfidences, commonPatternTypes, deliveryMechanisms,
  investigativeChecks, limitations, metricLabels, objectives, recommendationCaveats,
  recommendations, recommendationScopes, roles, sourceAuthenticities,
  sourcePopulations, uncertainties, warnings,
} from './ddosReportTranslations';

export type { DDoSAttackReport, DDoSFinding, DDoSSignatureCandidate, DDoSClassification, DDoSCommonPattern, DDoSRecommendation } from './ddosReportContract';
import { type DDoSAttackReport, isDDoSAttackReport } from './ddosReportContract';

function format(value: unknown, language: 'ko' | 'en'): string {
  if (value == null) return language === 'ko' ? '관찰되지 않음' : 'Not observed';
  if (typeof value === 'number' && Number.isFinite(value)) return value.toLocaleString('en-US', { maximumFractionDigits: 20 });
  if (typeof value === 'string' && value.length <= 80) return value;
  if (typeof value === 'boolean') return value ? (language === 'ko' ? '예' : 'Yes') : (language === 'ko' ? '아니요' : 'No');
  if (Array.isArray(value) && value.length <= 8 && value.every(item => typeof item === 'string')) return value.join(', ');
  return language === 'ko' ? '표시할 수 없음' : 'Unavailable';
}

const reportIdentities = new WeakMap<object, number>();
let nextReportIdentity = 0;
function reportIdentity(report: object) {
  if (!reportIdentities.has(report)) reportIdentities.set(report, ++nextReportIdentity);
  return reportIdentities.get(report)!;
}

function Content({ report, detailOwner, setDetailOwner, ownerPrefix, current, job }: {
  report: DDoSAttackReport;
  detailOwner: string | undefined;
  setDetailOwner: (owner: string | undefined) => void;
  ownerPrefix: string;
  current: () => boolean;
  job?: ExportJob;
}) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => language === 'ko' ? ko : en;
  const [page, setPage] = useState(0);
  if (!isDDoSAttackReport(report)) return <section className="panel ddos-report" role="alert">{t('Unsupported DDoS report. Review coverage and update the client.', '지원되지 않는 DDoS 보고서입니다. 분석 범위를 확인하고 클라이언트를 업데이트하세요.')}</section>;
  const coverageKey = `${ownerPrefix}:coverage`;
  const coverageOpen = detailOwner === coverageKey;
  const findings = report.findings;
  const primary = findings.find(item => item.id === report.primary_finding_id) ?? findings[0];
  const actionByCode = new Map(report.recommendations.map(item => [item.code, item]));

  const heading = report.verdict === 'attack_likely' ? t('DDoS attack likely', 'DDoS 공격 가능성 높음')
    : report.verdict === 'suspicious_traffic' ? t('Suspicious DDoS-shaped traffic observed', '의심스러운 DDoS 형태 관찰')
      : report.verdict === 'no_clear_attack' && report.summary.coverage_complete === true ? t('No clear DDoS attack observed', '뚜렷한 DDoS 공격 징후 없음')
        : t('Insufficient evidence for a DDoS conclusion', 'DDoS 결론을 위한 증거 부족');
  const visible = findings.slice(page * 8, page * 8 + 8);
  const pageCount = Math.max(1, Math.ceil(findings.length / 8));
  return <section className="panel ddos-report" aria-labelledby="ddos-heading">
    <section className="network-glance ddos-glance" role="region" aria-label={t('DDoS at a glance', 'DDoS 한눈에 보기')}>
      <p className="eyebrow">DDoS ATTACK TRAFFIC REPORT</p><h2 id="ddos-heading">{heading}</h2>
      <p>{report.verdict === 'no_clear_attack' ? t('No supported DDoS shape was observed; this does not prove a healthy service.', '지원되는 DDoS 형태가 관찰되지 않았지만 서비스가 정상임을 입증하지는 않습니다.') : t('This is a defensive traffic-shape assessment, not actor attribution or proof of service impact.', '이는 방어 목적의 트래픽 형태 평가이며 공격자 귀속이나 서비스 영향의 입증이 아닙니다.')}</p>
      {report.warnings.length > 0 && <p className="warning">{report.warnings.map(code => choose(language, warnings[code])).join(' ')}</p>}
      {report.omitted_finding_count > 0 && <p className="warning">{t('Findings omitted by producer:', '생산자가 생략한 발견 항목:')} {report.omitted_finding_count}</p>}
      {report.summary.counts_are_lower_bounds === true && <p className="warning">{t('Counts are lower bounds; retained evidence is truncated or incomplete.', '수치는 하한이며 보존 근거가 잘렸거나 불완전합니다.')}</p>}
      {primary && <div className="ddos-primary"><p className="eyebrow">{t('Selected target assessment — not a report-wide classification', '선택 대상 평가 — 보고서 전체의 분류가 아님')}</p><h3>{choose(language, attackTypes[primary.attack_type])}</h3>
        <p><strong>{t('Observed role', '관찰 역할')}</strong> — {choose(language, roles[primary.attack_role])}</p>
        <p><strong>{t('Target', '대상')}</strong> — <code>{primary.target.ip}{primary.target.port == null ? '' : `:${primary.target.port}`}</code> · {primary.protocol}</p>
        <p><strong>{t('Likely defensive objective — hypothesis', '추정 방어 목적 — 가설')}</strong> — {choose(language, objectives[primary.objective])}</p>
        {primary.classification && <div className="ddos-classification"><h3>{t('Attack delivery and source assessment', '공격 전달·source 평가')}</h3>
          <p><strong>{t('Delivery', '전달 방식')}</strong> — {choose(language, deliveryMechanisms[primary.classification.delivery_mechanism])}<small>{choose(language, classificationConfidences[primary.classification.axes?.delivery_mechanism.confidence ?? primary.classification.confidence])}</small></p>
          <p><strong>{t('Source population', 'Source 집단')}</strong> — {choose(language, sourcePopulations[primary.classification.source_population])}<small>{choose(language, classificationConfidences[primary.classification.axes?.source_population.confidence ?? primary.classification.confidence])}</small></p>
          <p><strong>{t('Source authenticity', 'Source 진위')}</strong> — {choose(language, sourceAuthenticities[primary.classification.source_authenticity])}<small>{choose(language, classificationConfidences[primary.classification.axes?.source_authenticity.confidence ?? primary.classification.confidence])}</small></p>
        </div>}
      </div>}
      <p className="muted">{t('Botnet-like is not confirmed botnet; unconfirmed authenticity is not proof of no spoofing; reflection is not measured amplification.', '봇넷 유사 형태는 확정 봇넷이 아니며, 진위 미확인은 spoofing 부재의 증명이 아닙니다. 반사는 측정된 증폭이 아닙니다.')}</p>
      {primary?.common_patterns && <section aria-label={t('Selected target patterns', '선택 대상 패턴')}><h3>{t('Key observed patterns', '주요 관찰 패턴')}</h3><ul className="ddos-top-patterns">{primary.common_patterns.slice(0, 3).map(pattern => <li key={pattern.id}>{choose(language, commonPatternTypes[pattern.type])} — {pattern.values.every(value => value.length < 48) ? pattern.values.join(', ') : t(`${pattern.values.length} comparison fingerprint(s); full values in details`, `비교 지문 ${pattern.values.length}개; 전체 값은 상세 참조`)} · {pattern.support_count} {t('supporting records', '지지 레코드')}</li>)}</ul></section>}
      <section className="ddos-next" role="region" aria-label={t('Next check', '다음 확인')}><h3>{t('Next check', '다음 확인')}</h3>
        <p>{t('Preserve the capture and correlate the observed target and time with service logs before any response. These are passive investigative checks, not mitigation instructions.', '대응 전에 캡처를 보존하고 관찰 대상·시각을 서비스 로그와 대조하세요. 이는 수동 조사 절차이며 완화 조치 지시가 아닙니다.')}</p>
        {primary ? <>
          <p>{choose(language, investigativeChecks[primary.attack_type])}</p>
          <p>{t('Observed time', '관찰 시각')}: {primary.first_seen} → {primary.last_seen}</p>
          <button type="button" className="secondary" aria-expanded={detailOwner === `${ownerPrefix}:finding:${primary.id}`} onClick={() => { if (current()) { setPage(Math.floor(findings.indexOf(primary) / 8)); setDetailOwner(`${ownerPrefix}:finding:${primary.id}`); } }}>{t('Review selected target evidence', '선택 대상 근거 검토')}</button>
          {Boolean(primary.signature_candidates?.length) && <p className="muted">{t('Inspect signature candidates in detailed evidence; reviewed JSON and supported passive exports remain subject to their evidence and ownership limits.', '상세 근거에서 시그니처 후보를 조사하세요. 검토용 JSON 및 지원되는 수동 export에는 근거와 소유권 제한이 유지됩니다.')}</p>}
        </> : <p>{t('Review analysis coverage, protected-side networks and capture visibility. No retained finding is not proof of normal traffic.', '분석 범위, 보호 측 네트워크 및 캡처 관측 범위를 검토하세요. 보존된 발견 항목 부재는 정상 트래픽의 증명이 아닙니다.')}</p>}
        <p className="muted">{t('The statistical baseline uses same-capture low-traffic buckets, not known-normal traffic. The optional operator-selected normal reference is for candidate predicate evaluation; selecting it does not upgrade flood likelihood or establish normality.', '통계 기준선은 정상으로 확인된 트래픽이 아니라 같은 캡처의 저트래픽 버킷을 사용합니다. 운영자가 선택한 정상 참조는 선택 사항이며 후보 조건식 평가용입니다. 이를 선택해도 플러드 가능성을 상향하지 않으며 정상성을 입증하지도 않습니다.')}</p>
      </section>
      {(report.warnings.length > 0 || report.summary.coverage_complete !== true) && <p className="warning">{t('Coverage is incomplete or qualified; absence of additional findings is not a clean result.', '분석 범위가 불완전하거나 조건부입니다. 추가 발견이 없더라도 정상 결과로 해석할 수 없습니다.')}</p>}
    </section>
    <button type="button" className="secondary" aria-expanded={coverageOpen} onClick={() => { if (current()) setDetailOwner(coverageOpen ? undefined : coverageKey); }}>{t('Analysis coverage and limitations', '분석 범위와 한계')}</button>
    {coverageOpen && <section role="region" aria-label={t('DDoS analysis coverage', 'DDoS 분석 범위')}><h3>{t('Coverage and limitations', '분석 범위 및 한계')}</h3>
      <p>{format(report.summary.evaluated_records, language)} {t('records evaluated', '개 레코드 평가')} · {format(report.summary.skipped_records, language)} {t('skipped', '개 제외')} · {format(report.summary.incomplete_records, language)} {t('incomplete', '개 불완전')}</p>
      <ul>{report.warnings.map(code => <li key={code}>{choose(language, warnings[code])} <code>{code}</code></li>)}{report.limitations.map(code => <li key={code}>{choose(language, limitations[code])}</li>)}</ul>
    </section>}
    <h3>{t('Attack findings', '공격 발견 항목')}</h3>
    {!findings.length && <p>{t('No DDoS finding was retained. Check coverage before interpreting this result.', '보존된 DDoS 발견 항목이 없습니다. 결과 해석 전 분석 범위를 확인하세요.')}</p>}
    {visible.map(item => {
      const findingKey = `${ownerPrefix}:finding:${item.id}`;
      const open = detailOwner === findingKey;
      return <article className="panel compact" key={item.id}><h4>{choose(language, attackTypes[item.attack_type])}</h4>
        <p><span className={`badge ${item.severity.toLowerCase()}`}>{item.likelihood} · {item.severity}</span> <code>{item.target.ip}{item.target.port == null ? '' : `:${item.target.port}`}</code></p>
        <p>{choose(language, objectives[item.objective])}</p>
        <button className="secondary" aria-expanded={open} onClick={() => { if (current()) setDetailOwner(open ? undefined : findingKey); }}>{open ? t('Hide detailed evidence', '상세 근거 숨기기') : t('Show detailed evidence', '상세 근거 보기')} — {choose(language, attackTypes[item.attack_type])}</button>
        {open && <section role="region" aria-label={t('DDoS finding evidence', 'DDoS 발견 근거')}>
          <h5>{t('Measured facts', '측정 사실')}</h5><dl>{Object.entries(item.metrics).map(([key, value]) => <div key={key}><dt>{choose(language, metricLabels[key])}</dt><dd>{format(value, language)}</dd></div>)}</dl>
          {item.classification?.axes && <div>{axisNames.map(name => {
            const axis = item.classification!.axes![name];
            return <div key={name}><p><strong>{t(name === 'delivery_mechanism' ? 'Delivery' : name === 'source_population' ? 'Source population' : 'Source authenticity', name === 'delivery_mechanism' ? '전달 방식' : name === 'source_population' ? 'Source 집단' : 'Source 진위')}</strong> — {choose(language, classificationConfidences[axis.confidence])}</p>
              {(['supporting_codes', 'counter_codes', 'unknown_codes'] as const).map(kind => axis[kind].length > 0 && <p key={kind}>
                {kind === 'supporting_codes' ? t('Supporting evidence: ', '지지 근거: ') : kind === 'counter_codes' ? t('Counterevidence: ', '반대 근거: ') : t('Unknowns: ', '미확인: ')}
                {axis[kind].map(code => t(...axisReasons[code])).join(' ')}
              </p>)}
            </div>;
          })}<p>{t(`Eligible sources: ${item.classification.evidence!.eligible_sources}; coordinated sources: ${item.classification.evidence!.coordinated_sources}; window: ${item.classification.evidence!.window_seconds} s; shared buckets: ${item.classification.evidence!.shared_buckets}.`, `적격 source: ${item.classification.evidence!.eligible_sources}; 조율 source: ${item.classification.evidence!.coordinated_sources}; 구간: ${item.classification.evidence!.window_seconds}초; 공통 버킷: ${item.classification.evidence!.shared_buckets}.`)}</p>
            <p>{t(`Retained packet samples: ${item.classification.evidence!.sample_count}; omitted: ${item.classification.evidence!.omitted_samples}; packets without sample evidence: ${item.classification.evidence!.unobserved_packets}.`, `보존 패킷 표본: ${item.classification.evidence!.sample_count}; 생략: ${item.classification.evidence!.omitted_samples}; 표본 근거 없는 패킷: ${item.classification.evidence!.unobserved_packets}.`)}</p>
          </div>}
          {item.classification && <><h5>{t('Classification', '공격 분류')}</h5><dl>
            <div><dt>{t('Delivery', '전달 방식')}</dt><dd>{choose(language, deliveryMechanisms[item.classification.delivery_mechanism])}</dd></div>
            <div><dt>{t('Source population', 'Source 집단')}</dt><dd>{choose(language, sourcePopulations[item.classification.source_population])}</dd></div>
            <div><dt>{t('Source authenticity', 'Source 진위')}</dt><dd>{choose(language, sourceAuthenticities[item.classification.source_authenticity])}</dd></div>
          </dl></>}
          {item.common_patterns && item.common_patterns.length > 0 && <><h5>{t('Common patterns', '공통 패턴')}</h5><ul>{item.common_patterns.map(pattern => <li key={pattern.id}>{choose(language, commonPatternTypes[pattern.type])} — {format(pattern.support_count, language)} {t('records', '레코드')} · {format(pattern.support_ratio, language)}{pattern.values.length ? ` · ${pattern.values.join(', ')}` : ''}</li>)}</ul></>}
          {item.signature_candidates && item.signature_candidates.length > 0 && <DDoSCandidateInspection finding={item} report={report} job={job} current={current}/>}
          <h5>{t('Uncertainty', '불확실성')}</h5><ul>{item.uncertainty_codes.map(code => <li key={code}>{choose(language, uncertainties[code])}</li>)}</ul>
          <h5>{t('Recommended responses', '권장 대응')}</h5><ul>{item.recommendation_codes.map(code => { const action = actionByCode.get(code)!; return <li key={code}>{choose(language, recommendations[code])} — {choose(language, recommendationScopes[action.scope])} — {choose(language, recommendationCaveats[code])} — {t('Human approval required', '운영자 승인 필요')}</li>; })}</ul>
          <p>{t('Observed time', '관찰 시각')}: {item.first_seen} → {item.last_seen}</p>
        </section>}
      </article>;
    })}
    {pageCount > 1 && <nav className="pagination" aria-label={t('DDoS finding pages', 'DDoS 발견 항목 페이지')}><button className="secondary" disabled={page === 0} onClick={() => { setPage(page - 1); setDetailOwner(undefined); }}>{t('Previous', '이전')}</button><span role="status" aria-live="polite">{page + 1} / {pageCount}</span><button className="secondary" disabled={page + 1 >= pageCount} onClick={() => { setPage(page + 1); setDetailOwner(undefined); }}>{t('Next', '다음')}</button></nav>}
  </section>;
}

export default function DDoSAttackPanel({ report, detailOwner, setDetailOwner, children, job }: {
  report: DDoSAttackReport;
  detailOwner?: string;
  setDetailOwner?: (owner: string | undefined) => void;
  children?: ReactNode;
  job?: ExportJob;
}) {
  const [localOwner, setLocalOwner] = useState<string>();
  const currentReport = useRef({ report, job });
  const active = useRef(true);
  currentReport.current = { report, job };
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  const current = () => active.current && currentReport.current.report === report && currentReport.current.job === job && isDDoSAttackReport(report);
  useEffect(() => {
    (setDetailOwner ?? setLocalOwner)(undefined);
  }, [report, job?.id, job?.dataset_id, setDetailOwner]);
  const signature = `${report.version}:${report.primary_finding_id ?? 'none'}:${String(report.summary?.finding_count ?? 'unknown')}`;
  return <ReportLanguageScope><>
    <Content
      key={`${reportIdentity(report)}:${job?.id ?? ''}:${job?.dataset_id ?? ''}`}
      report={report}
      current={current}
      job={job}
      detailOwner={setDetailOwner ? detailOwner : localOwner}
      setDetailOwner={setDetailOwner ?? setLocalOwner}
      ownerPrefix={`ddos:${job?.id ?? ''}:${job?.dataset_id ?? ''}:${reportIdentity(report)}:${signature}`}
    />
    {children}
  </></ReportLanguageScope>;
}
