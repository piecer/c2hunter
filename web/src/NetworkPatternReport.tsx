import { useState } from 'react';
import NetworkMeasurements, { CauseHypothesis } from './NetworkMeasurements';
import { useReportLanguage } from './reportLanguageContext';
import { choose, patterns, warnings as warningCodes, rawText, translateProse, patternLabel, warningLabel, factLabel, evidenceText } from './reportTranslations';

type Endpoint = { ip: string; port: number | null };
export type PatternIssue = {
  id: string; pattern: string; title: string; severity: string;
  scope: { sensor_id: string; interface_id: number | null; protocol: string; peer: Endpoint };
  event_count: number; affected_flow_count: number; affected_host_count: number;
  first_seen: string; last_seen: string;
  examples: { endpoint_a: Endpoint; endpoint_b: Endpoint; event_count: number; facts?: Record<string, number>; measurements?: unknown }[];
  suspected_cause?: unknown; detailed_analysis?: string[];
  omitted_examples: number; evidence: string[]; uncertainty: string[]; next_checks: string[];
};
export type PatternReport = {
  version: string; measurement_version?: string; summary: Record<string, unknown>; issues?: PatternIssue[];
  warnings: string[]; limitations: string[];
};
const summaryCounts = ['scanned_records', 'evaluated_records', 'skipped_records', 'incomplete_records', 'flow_count', 'suspect_flow_count', 'detailed_flow_count', 'issue_count', 'displayed_issue_count', 'omitted_issue_count'];
const count = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
function Notes({ values, issue, limit = 4 }: { values: unknown; issue?: PatternIssue; limit?: number }) {
  const language = useReportLanguage();
  const items = Array.isArray(values) ? values : [];
  return <ul>{items.slice(0, limit).map((value, index) => <li key={index}>{issue ? evidenceText(language, value, issue) : translateProse(language, value)}</li>)}{items.length > limit && <li>{items.length - limit} {choose(language, 'additional notes omitted from this view.', '개의 추가 참고 사항이 이 화면에서 생략되었습니다.')}</li>}</ul>;
}
export default function NetworkPatternReport({ report }: { report: PatternReport }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => choose(language, en, ko);
  const text = (value: unknown, max = 320) => rawText(language, value, max);
  const number = (value: unknown) => count(value)?.toLocaleString('en-US') ?? t('Unknown', '알 수 없음');
  const endpoint = (value?: Endpoint) => value && typeof value.ip === 'string' ? `${value.ip.includes(':') ? `[${text(value.ip, 80)}]` : text(value.ip, 80)}${value.port == null ? '' : `:${count(value.port) ?? t('unknown', '알 수 없음')}`}` : t('Endpoint not reported', '종단점이 보고되지 않음');
  const [expanded, setExpanded] = useState<{ report: PatternReport; index: number }>();
  const summary = report.summary ?? {};
  const issues = Array.isArray(report.issues) ? report.issues : [];
  const verdict = summary.verdict;
  const measurementsSupported = report.measurement_version === 'network-supporting-measurements-v1';
  const warnings = Array.isArray(report.warnings) ? report.warnings : [];
  const recognized = Array.isArray(report.issues) && Array.isArray(report.warnings) && summaryCounts.every(key => count(summary[key]) !== undefined) && warnings.every(warning => Object.hasOwn(warningCodes, warning)) && issues.every(issue => issue && Object.hasOwn(patterns, issue.pattern));
  const complete = recognized && warnings.length === 0 && summary.coverage_complete === true && summary.skipped_records === 0 && summary.incomplete_records === 0 && (count(summary.evaluated_records) ?? 0) > 0;
  const safeClear = complete && summary.issue_count === 0 && issues.length === 0 && summary.omitted_issue_count === 0 && summary.truncated === false;
  const heading = recognized && verdict === 'anomaly_observed' ? t('Anomaly observed', '이상 징후 관찰됨') : recognized && verdict === 'no_clear_anomaly' && safeClear ? t('No clear anomaly observed', '뚜렷한 이상 징후가 관찰되지 않음') : t('Insufficient data', '데이터 부족');
  return <section className="panel network-report" aria-labelledby="overall-network-heading">
    <p className="eyebrow">{t('OVERALL NETWORK REPORT', '전체 네트워크 보고서')}</p><h2 id="overall-network-heading">{heading}</h2>
    <p>{!recognized || (verdict === 'no_clear_anomaly' && !safeClear) ? t('Report fields are incomplete, unsupported or inconsistent; an overall conclusion cannot be confirmed.', '보고서 필드가 불완전하거나 지원되지 않거나 서로 일치하지 않아 종합 결론을 확정할 수 없습니다.') : translateProse(language, summary.narrative)}</p>
    {measurementsSupported && recognized && issues.length > 0 && summary.suspected_cause != null && <CauseHypothesis value={summary.suspected_cause} leading/>}
    <p className="muted">{t('Pattern scan → detailed analysis of identified patterns → one overall report. These are analysis stages, not live stage progress.', '패턴 검사 → 식별된 패턴의 상세 분석 → 하나의 종합 보고서. 이는 분석 절차이며 실시간 진행 상태가 아닙니다.')}</p>
    <p>{t('Transport observations are not C2 classifications. Shared patterns do not prove a shared root cause. Single-vantage evidence cannot prove path loss or a fault location.', '전송 계층 관찰 결과는 C2 분류가 아닙니다. 같은 패턴이 공통 근본 원인을 입증하지는 않습니다. 단일 관찰 지점의 증거로는 경로 손실이나 장애 위치를 입증할 수 없습니다.')}</p>
    {!measurementsSupported && <p className="warning">{t('RTT/latency, interarrival dispersion and TTL measurements are not computed by this pattern-first producer. Latency analysis is unsupported in new reports; existing saved legacy reports retain their original measurements behind the legacy toggle.', '이 패턴 우선 분석기는 RTT/지연 시간, 도착 간격 산포 및 TTL 측정값을 계산하지 않습니다. 새 보고서에서는 지연 시간 분석을 지원하지 않습니다. 이전에 저장된 보고서의 원래 측정값은 이전 형식 보기에서 확인할 수 있습니다.')}</p>}
    <section aria-label={t('Analysis coverage', '분석 범위')}><h3>{t('Coverage and omissions', '분석 범위 및 생략')}</h3>
      <p className={complete ? '' : 'warning'}>{complete ? t('Coverage complete for evaluated evidence; this is not proof of a healthy network.', '평가한 증거의 분석 범위는 완전하지만 네트워크가 정상임을 입증하지는 않습니다.') : t('Incomplete or unknown coverage — absence of findings cannot establish a healthy network.', '분석 범위가 불완전하거나 알려지지 않았습니다. 발견 사항이 없더라도 네트워크가 정상이라고 단정할 수 없습니다.')}</p>
      <p>{number(summary.scanned_records)} {t('records scanned', '개 레코드 검사')} · {number(summary.evaluated_records)} {t('evaluated', '개 평가')} · {number(summary.skipped_records)} {t('skipped', '개 건너뜀')} · {number(summary.incomplete_records)} {t('incomplete', '개 불완전')}</p>
      {summary.counts_are_lower_bounds === true && <p className="warning">{t('Counts are lower bounds, not complete capture totals.', '수치는 하한값이며 전체 캡처의 총계가 아닙니다.')} {number(summary.tracking_limited_records)} {t('records exceeded tracking limits; retained observations remain valid, but additional anomalies may be missing.', '개 레코드가 추적 한도를 초과했습니다. 보존된 관찰은 유효하지만 추가 이상 징후가 누락되었을 수 있습니다.')}</p>}
      <p>{number(summary.flow_count)} {t('flows scanned', '개 흐름 검사')} · {number(summary.suspect_flow_count)} {t('suspect flows', '개 의심 흐름')} · {number(summary.detailed_flow_count)} {t('representative flows analyzed in detail', '개 대표 흐름 상세 분석')}</p>
      <p>{number(summary.issue_count)} {t('issue groups', '개 문제 그룹')} · {Math.min(issues.length, 8)} {t('shown', '개 표시')} · {number(summary.omitted_issue_count)} {t('groups omitted by producer', '개 그룹 분석기에서 생략')} · {Math.max(0, issues.length - 8)} {t('additional groups omitted from this view', '개 추가 그룹 이 화면에서 생략')}</p>
      {summary.truncated === true && <p className="warning">{t('Report truncated: not all issue groups are included. Detection counts are not a complete list of displayed evidence.', '보고서 일부 생략: 모든 문제 그룹이 포함되지는 않았습니다. 탐지 수치에 해당하는 증거가 전부 표시된 것은 아닙니다.')}</p>}
      <ul>{warnings.slice(0, 8).map((warning, index) => <li key={index}>{warningLabel(language, warning)}</li>)}{warnings.length > 8 && <li>{warnings.length - 8} {t('additional coverage warnings omitted from this view.', '개의 추가 분석 범위 경고가 이 화면에서 생략되었습니다.')}</li>}</ul><Notes values={report.limitations} limit={8}/>
    </section>
    <h3>{t('Grouped observations', '그룹별 관찰 결과')}</h3>
    {!issues.length && <p>{t('No grouped observations retained. Consult coverage before interpreting this result.', '보존된 그룹별 관찰 결과가 없습니다. 결과를 해석하기 전에 분석 범위를 확인하세요.')}</p>}
    {!recognized && issues.slice(0, 8).filter(issue => issue && !Object.hasOwn(patterns, issue.pattern)).map((issue, index) => <p key={index}>{patternLabel(language, issue.pattern)}</p>)}
    {recognized && issues.slice(0, 8).map((issue, index) => {
      const open = expanded?.report === report && expanded.index === index;
      const examples = Array.isArray(issue.examples) ? issue.examples : [];
      return <article className="panel compact" key={index}>
        <h4>{patternLabel(language, issue.pattern)}</h4>
        <p>{t('Severity', '심각도')}: {issue.severity === 'observation' ? t('Observation', '관찰 사항') : translateProse(language, issue.severity)}</p>
        <p>{number(issue.event_count)} {t('events', '건')} · {number(issue.affected_flow_count)} {t('affected flows', '개 영향받은 흐름')} · {number(issue.affected_host_count)} {t('affected hosts', '개 영향받은 호스트')}</p>
        <p>{t('Affected range:', '영향 범위:')} {text(issue.scope?.sensor_id, 80)} · {t('interface', '인터페이스')} {issue.scope?.interface_id == null ? t('unknown', '알 수 없음') : number(issue.scope.interface_id)} · {text(issue.scope?.protocol, 12)} · {t('peer', '상대')} {endpoint(issue.scope?.peer)}</p>
        <p>{t('Observed time:', '관찰 시간:')} {text(issue.first_seen, 40)} → {text(issue.last_seen, 40)}</p>
        {measurementsSupported && <CauseHypothesis value={issue.suspected_cause}/>}
        <h5>{t('Representative proof', '대표 증거')}</h5><Notes values={issue.evidence} issue={issue}/>
        <h5>{t('Uncertainty', '불확실성')}</h5><Notes values={issue.uncertainty}/>
        <h5>{t('Next checks', '다음 확인 사항')}</h5><Notes values={issue.next_checks}/>
        <button className="secondary" aria-expanded={open} aria-controls={`network-evidence-${index}`} onClick={() => setExpanded(open ? undefined : { report, index })}>{open ? t('Hide', '숨기기') : t('Show', '보기')} {t('representative evidence', '대표 증거')} — {patternLabel(language, issue.pattern)}</button>
        {open && <section id={`network-evidence-${index}`} aria-label={t('Representative flow evidence', '대표 흐름 증거')}>
          {!examples.length && <p>{t('No representative flow examples were included.', '대표 흐름 예시가 포함되지 않았습니다.')}</p>}
          <ul>{examples.slice(0, 3).map((example, i) => <li key={i}>{endpoint(example.endpoint_a)} ↔ {endpoint(example.endpoint_b)} · {number(example.event_count)} {t('events', '건')}<ul>{Object.entries(example.facts ?? {}).slice(0, 8).map(([key, value]) => <li key={key}>{factLabel(language, key)}: {typeof value === 'number' && Number.isFinite(value) ? String(value) : t('Unknown', '알 수 없음')}</li>)}{Object.keys(example.facts ?? {}).length > 8 && <li>{Object.keys(example.facts ?? {}).length - 8} {t('additional facts omitted from this view.', '개의 추가 사실이 이 화면에서 생략되었습니다.')}</li>}</ul>{measurementsSupported && <NetworkMeasurements value={example.measurements}/>}</li>)}</ul>
          <p>{number(issue.omitted_examples)} {t('examples omitted by producer', '개 예시 분석기에서 생략')} · {Math.max(0, examples.length - 3)} {t('additional examples omitted from this view. Only retained evidence is available here; no additional data is fetched.', '개 추가 예시 이 화면에서 생략. 보존된 증거만 제공되며 추가 데이터를 가져오지 않습니다.')}</p>
        </section>}
      </article>;
    })}
  </section>;
}
