import { useNetworkEvidence } from './networkEvidenceContext';
import NetworkICMPDetails from './NetworkICMPDetails';
import type { ICMPResult } from './networkICMPDetails';
import { projectNetworkReport } from './networkReportValidation';
import { useReportDetail } from './reportDetailContext';
import { useCallback, useRef, useState } from 'react';
import NetworkMeasurements, { CauseHypothesis } from './NetworkMeasurements';
import { useReportLanguage } from './reportLanguageContext';
import { choose, diagnostics, rawText, translateProse, patternLabel, warningLabel, factLabel, evidenceText } from './reportTranslations';

type Endpoint = { ip: string; port: number | null };
export type PatternIssue = {
  id: string; pattern: string; title: string; severity: string;
  scope: { sensor_id: string; interface_id: number | null; protocol: string; peer: Endpoint };
  event_count: number; affected_flow_count: number; affected_host_count: number;
  first_seen: string; last_seen: string;
  examples: { endpoint_a: Endpoint; endpoint_b: Endpoint; event_count: number; facts?: Record<string, number>; measurements?: unknown; icmpDetails?: ICMPResult }[];
  suspected_cause?: unknown; detailed_analysis?: string[];
  omitted_examples: number; evidence: string[]; uncertainty: string[]; next_checks: string[];
};
export type PatternReport = {
  family_coverage?: unknown;
  version: string; measurement_version?: string; summary: Record<string, unknown>; issues?: PatternIssue[];
  warnings: string[]; limitations: string[];
};
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
  const [page, setPage] = useState(0);
  const [groupsOpen, setGroupsOpen] = useState(false);
  const detail = useReportDetail();
  const [coverageExpanded, setCoverageOpen] = useState(false);
  const coverageOpen = coverageExpanded && (!detail || detail.owner === 'coverage');
  const pageStatus = useRef<HTMLParagraphElement>(null);
  const groupsHeading = useRef<HTMLHeadingElement>(null);
  const focusEvidence = useRef(false);
  const retainFocus = useCallback((node: HTMLElement | null) => {
    if (!node) return;
    // Ref cleanup runs before removal; do not strand focus in a deleted page.
    return () => {
      if (node.contains(document.activeElement)) groupsHeading.current?.focus();
    };
  }, []);
  const [expanded, setExpanded] = useState<{ report: PatternReport; index: number }>();
  const evidence = useNetworkEvidence();
  const [request, setRequest] = useState(evidence?.selection);
  if (evidence?.selection && request !== evidence.selection) {
    setRequest(evidence.selection);
    setPage(Math.floor(evidence.selection.index / 8));
    setGroupsOpen(true);
    setCoverageOpen(false);
    setExpanded({ report, index: evidence.selection.index });
    focusEvidence.current = true;
  }
  const [owner, setOwner] = useState(report);
  // Identity, not counts/issue IDs: a replacement may have the same groups but
  // different evidence. Reset before committing children; never revive A on A→B→A.
  if (owner !== report) {
    setOwner(report);
    setPage(0);
    setGroupsOpen(false);
    setCoverageOpen(false);
    setExpanded(undefined);
  }
  const projection = projectNetworkReport(report);
  const summary = projection.summary;
  const family = projection.familyCoverage;
  const issues = projection.slots;
  const positives = issues.filter(slot => slot.issue);
  const pages = Math.max(1, Math.ceil(issues.length / 8));
  const current = Math.min(page, pages - 1);
  const selectedIndex = expanded?.report === report ? expanded.index : undefined;
  const visibleIssues = groupsOpen ? issues.slice(current * 8, current * 8 + 8) : selectedIndex === undefined ? [] : issues.slice(selectedIndex, selectedIndex + 1);
  const inspectIssue = (index: number) => {
    setGroupsOpen(false);
    setCoverageOpen(false);
    detail?.claim('evidence');
    setExpanded({ report, index });
    focusEvidence.current = true;
  };
  const changePage = (next: number) => {
    setPage(next);
    setExpanded(undefined);
    pageStatus.current?.focus();
  };
  const verdict = summary.verdict;
  const measurementsSupported = report.measurement_version === 'network-supporting-measurements-v1';
  const { knownWarnings, firstUnsupported, unsupportedWarnings: unsupportedCount } = projection;
  const warnings = { length: projection.warningsCount };
  const recognized = projection.summaryTrusted;
  const complete = recognized && warnings.length === 0 && summary.coverage_complete === true && summary.skipped_records === 0 && summary.incomplete_records === 0 && (count(summary.evaluated_records) ?? 0) > 0;
  const safeClear = family.state !== 'invalid' && complete && summary.issue_count === 0 && issues.length === 0 && summary.omitted_issue_count === 0 && summary.truncated === false;
  const heading = recognized && verdict === 'anomaly_observed' ? t('Anomaly observed', '이상 징후 관찰됨') : recognized && verdict === 'no_clear_anomaly' && safeClear ? t('No clear anomaly observed', '뚜렷한 이상 징후가 관찰되지 않음') : t('Insufficient data', '데이터 부족');
  return <section className="panel network-report" aria-labelledby="overall-network-heading">
    {projection.issueLimit && <p role="alert">{t('Report structure limit exceeded.', '보고서 구조 한도 초과.')}</p>}
    {projection.warningLimit && <p role="alert">{t('Warning collection limit exceeded.', '경고 목록 한도 초과.')}</p>}
    {issues.some(s => s.invalid || s.examplesInvalid || s.examplesExceeded) && <p className="warning">{t('Invalid or unsupported local evidence is omitted; valid observations remain available.', '잘못되었거나 지원되지 않는 일부 증거는 생략되며 유효한 관찰은 계속 표시됩니다.')}</p>}
    {!recognized && <p role="alert">{t('Invalid or inconsistent report data; an overall conclusion cannot be confirmed.', '잘못되었거나 일치하지 않는 보고서 데이터입니다. 종합 결론을 확인할 수 없습니다.')}</p>}
    <section aria-label={t('At a glance', '한눈에 보기')} className="network-glance" data-tone={recognized && verdict === 'anomaly_observed' ? 'observed' : safeClear && verdict === 'no_clear_anomaly' ? 'clear' : 'insufficient'}>
      <p className="eyebrow">{t('OVERALL NETWORK REPORT', '전체 네트워크 보고서')}</p><h2 id="overall-network-heading">{heading}</h2>
      <p data-testid="network-verdict">{heading === t('Anomaly observed', '이상 징후 관찰됨') ? t('Observable anomaly patterns need review; this does not establish a root cause or C2 activity.', '관찰된 이상 패턴을 확인해야 하며, 원인이나 C2 활동이 확정된 것은 아닙니다.') : safeClear && verdict === 'no_clear_anomaly' ? t('No supported anomaly pattern was observed in the evaluated evidence; this does not prove a healthy network.', '평가한 증거에서 지원되는 이상 패턴이 관찰되지 않았지만 네트워크가 정상임을 입증하지는 않습니다.') : t('Available evidence cannot support an overall conclusion; check coverage first.', '현재 증거로 종합 결론을 내릴 수 없으므로 분석 범위를 먼저 확인하세요.')}</p>
      <div role="group" aria-label={t('Report totals', '보고서 전체 수치')} className="network-totals">
        <div><strong>{number(summary.suspect_flow_count)}</strong><span>{t('suspect flows', '의심 흐름')}</span></div>
        <div><strong>{number(summary.flow_count)}</strong><span>{t('flows scanned', '검사한 흐름')}</span></div>
        <div><strong>{number(summary.issue_count)}</strong><span>{t('issue groups', '문제 그룹')}</span></div>
      </div>
      {!complete && <p className="warning">{t('Incomplete or unknown coverage — absence of findings cannot establish a healthy network.', '분석 범위가 불완전하거나 알려지지 않았습니다. 발견 사항이 없더라도 네트워크가 정상이라고 단정할 수 없습니다.')} {warnings.length} {t('coverage warnings', '개 범위 경고')} · {number(summary.skipped_records)} {t('skipped', '개 건너뜀')} · {number(summary.incomplete_records)} {t('incomplete', '개 불완전')}</p>}
      {summary.counts_are_lower_bounds === true && <p className="warning">{t('Counts are lower bounds, not complete capture totals.', '수치는 하한값이며 전체 캡처의 총계가 아닙니다.')} {number(summary.tracking_limited_records)} {t('records exceeded tracking limits; additional anomalies may be missing.', '개 레코드가 추적 한도를 초과하여 추가 이상 징후가 누락되었을 수 있습니다.')}</p>}
      {summary.truncated === true && <p className="warning">{t('Report truncated: retained evidence is not the complete result.', '보고서 일부 생략: 보존된 증거는 전체 결과가 아닙니다.')} {number(summary.omitted_issue_count)} {t('groups omitted by producer', '개 그룹 분석기에서 생략')}</p>}
      {family.state === 'invalid' && <p className="warning" role="alert">{t('Invalid family coverage — selection coverage is unknown; valid observations remain available.', '종류별 보존 범위가 잘못되어 선택 범위를 알 수 없습니다. 유효한 관찰은 계속 제공됩니다.')}</p>}
      {family.state === 'absent' && <p className="muted">{t('Family selection coverage was not recorded; omitted families are unknown.', '종류별 선택 범위가 기록되지 않아 생략된 종류를 알 수 없습니다.')}</p>}
      {family.state === 'valid' && <p className="muted">{t('Observed families without retained groups:', '관측되었으나 그룹이 보존되지 않은 종류:')} {family.value.families.filter(row => row.retained_groups === 0).length} · {t('Family-first selection; see coverage details. Detection limits still apply.', '종류 우선 선택입니다. 분석 범위 상세를 확인하세요. 탐지 한계는 여전히 적용됩니다.')}</p>}
      <div className="network-guidance">
        <section aria-label={t('Next action', '다음 행동')} className="network-next-action">
          <h3>{t('Priority next check', '우선 확인 사항')}</h3>
          <p>{positives.length ? choose(language, ...diagnostics[positives[0].issue!.pattern][2]) : safeClear && verdict === 'no_clear_anomaly' ? t('If symptoms persist, compare another observation period or capture point.', '증상이 지속되면 다른 관찰 기간이나 캡처 지점과 비교하세요.') : t('Check capture coverage and missing evidence before drawing conclusions.', '결론을 내리기 전에 캡처 범위와 누락된 증거를 확인하세요.')}</p>
        </section>
        {positives.length > 0 && measurementsSupported && summary.suspected_cause != null && <div className="network-cause"><CauseHypothesis value={summary.suspected_cause} leading compact/></div>}
      </div>
      {positives.length > 0 && <><h3>{t('First observations to inspect', '먼저 확인할 관찰 결과')}</h3>
        <ol className="network-key-patterns">{positives.slice(0, 3).map(({ issue: validIssue, index: i }) => { const issue = validIssue!; return <li data-testid="top-observation" key={i}>
          <strong>{patternLabel(language, issue.pattern)}</strong>
          <span className="network-peer">{endpoint(issue.scope?.peer)} <small>{text(issue.scope?.protocol, 12)}</small></span>
          <span className="network-group-counts">{number(issue.event_count)} {t('events', '건')} · {number(issue.affected_flow_count)} {t('affected flows', '개 영향받은 흐름')} · {number(issue.affected_host_count)} {t('affected hosts', '개 영향받은 호스트')}</span>
          <button type="button" className="secondary" onClick={() => inspectIssue(i)}>{t('Inspect evidence', '근거 확인')}<span className="sr-only"> — {patternLabel(language, issue.pattern)} · {endpoint(issue.scope?.peer)}</span><span aria-hidden="true"> →</span></button>
        </li>; })}</ol>
        <p className="network-order-note muted">{t('Up to 3 groups · producer order, not a risk ranking · group counts may overlap.', '최대 3개 그룹 · 분석기 순서이며 위험도 순위 아님 · 그룹별 수치는 중복될 수 있음')}</p>
      </>}
    </section>
    <button type="button" className="secondary" aria-expanded={coverageOpen} aria-controls={coverageOpen ? 'network-coverage' : undefined} onClick={() => { setCoverageOpen(!coverageOpen); detail?.claim('coverage'); setExpanded(undefined); }}>{t('Coverage details and limitations', '분석 범위 상세 및 한계')}</button>
    {coverageOpen && <section id="network-coverage" aria-label={t('Analysis coverage', '분석 범위')}>
      <h3>{t('Coverage and omissions', '분석 범위 및 생략')}</h3>
      <p>{!recognized || (verdict === 'no_clear_anomaly' && !safeClear) ? t('Report fields are incomplete, unsupported or inconsistent; an overall conclusion cannot be confirmed.', '보고서 필드가 불완전하거나 지원되지 않거나 서로 일치하지 않아 종합 결론을 확정할 수 없습니다.') : translateProse(language, summary.narrative)}</p>
      <p className="muted">{t('Pattern scan → detailed analysis of identified patterns → one overall report. These are analysis stages, not live stage progress.', '패턴 검사 → 식별된 패턴의 상세 분석 → 하나의 종합 보고서. 이는 분석 절차이며 실시간 진행 상태가 아닙니다.')}</p>
      <p>{t('Transport observations are not C2 classifications. Shared patterns do not prove a shared root cause. Single-vantage evidence cannot prove path loss or a fault location.', '전송 계층 관찰 결과는 C2 분류가 아닙니다. 같은 패턴이 공통 근본 원인을 입증하지는 않습니다. 단일 관찰 지점의 증거로는 경로 손실이나 장애 위치를 입증할 수 없습니다.')}</p>
      {!measurementsSupported && <p className="warning">{t('RTT/latency, interarrival dispersion and TTL measurements are not computed by this pattern-first producer. Existing saved legacy reports retain their original measurements behind the legacy toggle.', '이 패턴 우선 분석기는 RTT/지연 시간, 도착 간격 산포 및 TTL 측정값을 계산하지 않습니다. 이전에 저장된 보고서의 원래 측정값은 이전 형식 보기에서 확인할 수 있습니다.')}</p>}
      <p>{number(summary.scanned_records)} {t('records scanned', '개 레코드 검사')} · {number(summary.evaluated_records)} {t('evaluated', '개 평가')} · {number(summary.skipped_records)} {t('skipped', '개 건너뜀')} · {number(summary.incomplete_records)} {t('incomplete', '개 불완전')}</p>
      <p>{number(summary.detailed_flow_count)} {t('representative flows analyzed in detail', '개 대표 흐름 상세 분석')}</p>
      <ul>{Array.from(knownWarnings, warning => <li key={warning}>{warningLabel(language, warning)}</li>)}{unsupportedCount > 0 && <li>{warningLabel(language, firstUnsupported)}</li>}{unsupportedCount > 1 && <li>{unsupportedCount - 1} {t('additional unsupported warnings omitted from this view.', '개의 추가 미지원 경고가 이 화면에서 생략되었습니다.')}</li>}</ul><Notes values={projection.limitations} limit={8}/>
      {family.state === 'valid' && <section aria-label={t('Family selection coverage', '종류별 선택 범위')}>
        <p>{t('One representative per observed family first, then remaining groups by frequency. If slots are fewer than families, highest-ranked representatives are retained. Display order remains frequency order, not a risk ranking.', '관측된 종류마다 대표 그룹을 먼저 보존하고 남은 자리는 빈도순으로 채웁니다. 자리가 종류 수보다 적으면 같은 순위의 상위 대표만 보존합니다. 표시는 빈도순이며 위험도 순위가 아닙니다.')}</p>
        <p>{t('Counts describe observed issue groups, not capture-wide totals; coverage warnings still apply. No additional omitted evidence is fetched here.', '수치는 관측된 문제 그룹이며 전체 캡처 총계가 아닙니다. 분석 범위 경고가 계속 적용됩니다. 생략된 증거를 여기서 추가로 가져오지 않습니다.')}</p>
        <ul>{family.value.families.map(row => <li key={row.pattern}><strong>{patternLabel(language, row.pattern)}</strong> · {row.observed_groups} {t('observed groups', '개 관측 그룹')} · {row.retained_groups} {t('retained', '개 보존')} · {row.omitted_groups} {t('omitted', '개 생략')}{row.retained_groups === 0 && <span> — {t('Observed, but no group retained', '관측되었으나 보존된 그룹 없음')}</span>}</li>)}</ul>
        {!family.value.families.length && <p>{t('No supported family observed; consult overall coverage.', '지원되는 종류가 관측되지 않았습니다. 전체 분석 범위를 확인하세요.')}</p>}
      </section>}
    </section>}
    {issues.filter(slot => slot.unsupportedPattern).slice(0, 8).map(slot => <p key={slot.index}>{patternLabel(language, slot.unsupportedPattern!)}</p>)}
    <h3 ref={groupsHeading} tabIndex={-1}>{t('Grouped observations', '그룹별 관찰 결과')}</h3>
    <button type="button" className="secondary" aria-expanded={groupsOpen} onClick={() => { setGroupsOpen(!groupsOpen); setExpanded(undefined); }}>{t('View all anomaly items', '전체 이상 항목 보기')}</button>
    {groupsOpen && <p>{number(summary.issue_count)} {t('issue groups', '개 문제 그룹')} · {visibleIssues.length} {t('shown on this page', '개 현재 페이지에 표시')} · {number(summary.omitted_issue_count)} {t('groups omitted by producer', '개 그룹 분석기에서 생략')} · {issues.length - visibleIssues.length} {t('retained groups not shown on this page', '개 보존된 그룹 현재 페이지에 표시되지 않음')}</p>}
    {!issues.length && <p>{t('No grouped observations retained. Consult coverage before interpreting this result.', '보존된 그룹별 관찰 결과가 없습니다. 결과를 해석하기 전에 분석 범위를 확인하세요.')}</p>}

    {groupsOpen && issues.length > 8 && <nav ref={retainFocus} aria-label={t('Issue group pages', '문제 그룹 페이지')}>
      <button type="button" className="secondary" disabled={current === 0} onClick={() => changePage(current - 1)}>{t('Previous groups', '이전 그룹')}</button>
      <p ref={pageStatus} role="status" aria-live="polite" aria-atomic="true" tabIndex={-1}>{t(`Page ${current + 1} of ${pages}`, `${pages}페이지 중 ${current + 1}페이지`)}</p>
      <button type="button" className="secondary" disabled={current === pages - 1} onClick={() => changePage(current + 1)}>{t('Next groups', '다음 그룹')}</button>
    </nav>}
    {visibleIssues.map(slot => {
      const { index, issue } = slot;
      if (!issue) return <article className="panel compact" key={index}><p>{t('Invalid or unsupported issue data', '잘못되었거나 지원되지 않는 이슈 데이터')} · {index + 1}</p></article>;
      const open = expanded?.report === report && expanded.index === index && (!detail || detail.owner === 'evidence');
      const examples = Array.isArray(issue.examples) ? issue.examples : [];
      return <article ref={retainFocus} className="panel compact" key={index}>
        <h4>{patternLabel(language, issue.pattern)}</h4>
        <p style={{ overflowWrap: 'anywhere' }}>{t('Issue ID', '이슈 ID')}: <code>{issue.id || t('Not reported', '미제공')}</code></p>
        <p>{t('Severity', '심각도')}: {issue.severity === 'observation' ? t('Observation', '관찰 사항') : translateProse(language, issue.severity)}</p>
        <p>{number(issue.event_count)} {t('events', '건')} · {number(issue.affected_flow_count)} {t('affected flows', '개 영향받은 흐름')} · {number(issue.affected_host_count)} {t('affected hosts', '개 영향받은 호스트')}</p>
        <p>{t('Affected range:', '영향 범위:')} {text(issue.scope?.sensor_id, 80)} · {t('interface', '인터페이스')} {issue.scope?.interface_id == null ? t('unknown', '알 수 없음') : number(issue.scope.interface_id)} · {text(issue.scope?.protocol, 12)} · {t('peer', '상대')} {endpoint(issue.scope?.peer)}</p>
        <button className="secondary" aria-expanded={open} aria-controls={open ? `network-evidence-${index}` : undefined} onClick={() => { setCoverageOpen(false); detail?.claim('evidence'); setExpanded(open ? undefined : { report, index }); }}>{open ? t('Hide', '숨기기') : t('Show', '보기')} {t('representative evidence', '대표 증거')} — {patternLabel(language, issue.pattern)}</button>
        {open && <section id={`network-evidence-${index}`} tabIndex={-1} ref={node => { if (node && focusEvidence.current) { focusEvidence.current = false; node.focus(); node.scrollIntoView?.({ block: 'center' }); } }} aria-label={t('Representative flow evidence', '대표 흐름 증거')}>
        <p>{t('Observed time:', '관찰 시간:')} {text(issue.first_seen, 40)} → {text(issue.last_seen, 40)}</p>
        {measurementsSupported && <CauseHypothesis value={issue.suspected_cause}/>}
        {slot.examplesInvalid && <p className="warning">{t('Invalid example or fact fields; valid siblings are retained.', '잘못된 예시 또는 사실 필드입니다. 유효한 다른 증거는 보존됩니다.')}</p>}
        {slot.examplesExceeded && <p className="warning">{t('Example collection limit exceeded.', '예시 목록 한도 초과.')}</p>}
        {slot.notesMissing && <p>{t('Evidence notes not reported.', '증거 참고 사항 미제공.')}</p>}
        <h5>{t('Representative proof', '대표 증거')}</h5><Notes values={issue.evidence} issue={issue}/>
        <h5>{t('Uncertainty', '불확실성')}</h5><Notes values={issue.uncertainty}/>
        <h5>{t('Next checks', '다음 확인 사항')}</h5><Notes values={issue.next_checks}/>

          {!examples.length && <p>{t('No representative flow examples were included.', '대표 흐름 예시가 포함되지 않았습니다.')}</p>}
          {issue.pattern === 'icmp_errors' && examples.length > 0 && <NetworkICMPDetails key={index} values={examples.map(e => e.icmpDetails)}/>}
          <ul>{examples.slice(0, 3).map((example, i) => <li key={i}>{endpoint(example.endpoint_a)} ↔ {endpoint(example.endpoint_b)} · {number(example.event_count)} {t('events', '건')}{example.facts === undefined && <p>{t('Numeric facts not reported.', '수치 사실 미제공.')}</p>}<ul>{Object.entries(example.facts ?? {}).slice(0, 8).map(([key, value]) => <li key={key}>{factLabel(language, key)}: {typeof value === 'number' && Number.isFinite(value) ? String(value) : t('Unknown', '알 수 없음')}</li>)}{Object.keys(example.facts ?? {}).length > 8 && <li>{Object.keys(example.facts ?? {}).length - 8} {t('additional facts omitted from this view.', '개의 추가 사실이 이 화면에서 생략되었습니다.')}</li>}</ul>{measurementsSupported && <NetworkMeasurements value={example.measurements}/>}</li>)}</ul>
          <p>{number(issue.omitted_examples)} {t('examples omitted by producer', '개 예시 분석기에서 생략')} · {Math.max(0, examples.length - 3)} {t('additional examples omitted from this view. Only retained evidence is available here; no additional data is fetched.', '개 추가 예시 이 화면에서 생략. 보존된 증거만 제공되며 추가 데이터를 가져오지 않습니다.')}</p>
        </section>}
      </article>;
    })}
  </section>;
}
