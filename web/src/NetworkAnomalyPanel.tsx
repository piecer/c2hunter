import { useState } from 'react';
import ReportLanguageScope from './ReportLanguage';
import { useReportLanguage } from './reportLanguageContext';
import { choose, factLabel, translateProse, warningLabel } from './reportTranslations';
import NetworkPatternReport, { type PatternIssue } from './NetworkPatternReport';

type Endpoint = { ip: string; port: number | null };
type NetworkFlow = {
  sensor_id: string; interface_id: number | null; protocol: string;
  endpoint_a: Endpoint; endpoint_b: Endpoint;
  observed_directions: Record<string, { packets: number; bytes: number }>;
  metrics: Record<string, unknown>; warnings: string[];
  confidence?: unknown; findings?: unknown; evidence?: unknown;
};
export type NetworkAnomalyReport = {
  version: string; summary: Record<string, unknown>; flows: NetworkFlow[];
  warnings: string[]; limitations: string[]; issues?: PatternIssue[];
};
const endpoint = (value: Endpoint) => `${value.ip.includes(':') ? `[${value.ip}]` : value.ip}${value.port === null ? '' : `:${value.port}`}`;
const metrics = [
  ['syn_retransmissions', 'SYN retries'], ['data_retransmissions', 'Data retransmissions'],
  ['duplicate_acks', 'Duplicate ACKs'], ['observed_rtt_ms', 'Observed RTT (ms)'],
  ['interarrival_variation_ms', 'Interarrival variation (ms)'],
  ['udp_duplicate_candidates', 'UDP duplicate candidates'], ['icmp_errors', 'ICMP errors'],
] as const;

function CompactEvidence({ value }: { value: unknown }) {
  const language = useReportLanguage();
  // Format keys, not data. Serialize entries directly so localized keys cannot
  // collide and silently discard an original observation. String values stay raw.
  const format = (item: unknown, depth = 0): string => {
    if (item === null || typeof item !== 'object') return JSON.stringify(item) ?? String(item);
    const pad = '  '.repeat(depth + 1);
    if (Array.isArray(item)) return `[${item.map(child => format(child, depth + 1)).join(', ')}]`;
    return `{\n${Object.entries(item).map(([key, child]) => `${pad}${JSON.stringify(factLabel(language, key))}: ${format(child, depth + 1)}`).join(',\n')}\n${'  '.repeat(depth)}}`;
  };
  return <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', minWidth: 100, maxWidth: 280, maxHeight: 280, overflow: 'auto', fontSize: '0.75rem' }}>{typeof value === 'object' ? format(value) : String(value)}</pre>;
}
export default function NetworkAnomalyPanel({ report }: { report?: NetworkAnomalyReport }) {
  return <ReportLanguageScope><ReportContent report={report}/></ReportLanguageScope>;
}
function ReportContent({ report }: { report?: NetworkAnomalyReport }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => choose(language, en, ko);
  const [legacy, setLegacy] = useState<NetworkAnomalyReport>();
  if (!report) return <section className="panel"><h2>{t('Overall network report', '전체 네트워크 보고서')}</h2><p role="status">{t('No network report is available yet. Check job status and errors.', '아직 네트워크 보고서가 없습니다. 작업 상태와 오류를 확인하세요.')}</p></section>;
  if (report.version === 'network-pattern-report-v1') return <NetworkPatternReport report={report}/>;
  return <section className="panel"><h2>{t('Legacy report', '이전 형식 보고서')}</h2><p>{t('An overall verdict is unavailable for this saved report. Re-run analysis to produce a pattern-first report.', '이 저장된 보고서에는 종합 판정이 없습니다. 패턴 우선 보고서를 생성하려면 분석을 다시 실행하세요.')}</p><button className="secondary" aria-expanded={legacy === report} onClick={() => setLegacy(legacy === report ? undefined : report)}>{legacy === report ? t('Hide', '숨기기') : t('Show', '보기')} {t('legacy flow observations', '이전 형식 흐름 관찰')}</button>{legacy === report && <LegacyNetworkObservations report={report}/>}</section>;
}
function LegacyNetworkObservations({ report }: { report: NetworkAnomalyReport }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => choose(language, en, ko);
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(report.flows.length / 25));
  const current = Math.min(page, pages - 1);
  return <section className="panel" aria-labelledby="network-observations-heading">
    <p className="eyebrow">{t('NETWORK ANOMALY', '네트워크 이상 징후')} · {report.version}</p><h2 id="network-observations-heading">{t('Network observations', '네트워크 관찰 결과')}</h2>
    <p>{t('Transport observations are not C2 classifications. Single-vantage evidence cannot prove path loss, asymmetric routing, or a fault location.', '전송 계층 관찰 결과는 C2 분류가 아닙니다. 단일 관찰 지점의 증거로는 경로 손실, 비대칭 라우팅 또는 장애 위치를 입증할 수 없습니다.')}</p>
    <p className="muted">{t('Stored metric values and unknown fields are shown in their original form; only known labels and explanations are translated.', '저장된 측정값과 알 수 없는 필드는 원래 형태로 표시하며 알려진 항목명과 설명만 번역합니다.')}</p>
    <details open><summary>{t('Capture confidence and limitations', '캡처 신뢰도 및 한계')}</summary><ul>{report.limitations.map((text, index) => <li key={index}>{translateProse(language, text)}</li>)}</ul><CompactEvidence value={report.summary}/></details>
    {report.warnings.map((warning, index) => <p className="warning" key={index}>{warningLabel(language, warning, true)}</p>)}
    {!report.flows.length ? <p>{t('No supported flows observed; this is not evidence of a healthy path.', '지원되는 흐름이 관찰되지 않았습니다. 이는 경로가 정상이라는 증거가 아닙니다.')}</p> : <>
      <div className="table-wrap"><table aria-label={t('Bidirectional network flows', '양방향 네트워크 흐름')}><thead><tr><th>{t('Flow A ↔ B', '흐름 A ↔ B')}</th><th>{t('Observation point', '관찰 지점')}</th><th>{t('Packets / bytes by direction', '방향별 패킷 / 바이트')}
      </th>{metrics.map(([key, label]) => <th key={key}>{language === 'ko' ? factLabel(language, key) : label}</th>)}<th>{t('Evidence / confidence / warnings', '증거 / 신뢰도 / 경고')}</th></tr></thead><tbody>
        {report.flows.slice(current * 25, current * 25 + 25).map((flow, index) => <tr key={index}>
          <td><strong>{endpoint(flow.endpoint_a)}</strong><small>↔ {endpoint(flow.endpoint_b)}</small>{flow.protocol}</td>
          <td>{flow.sensor_id}<small>{t('Interface', '인터페이스')} {flow.interface_id ?? t('unknown', '알 수 없음')}</small></td>
          <td>{Object.entries(flow.observed_directions).map(([direction, counts]) => <div key={direction}>{direction === 'a_to_b' ? 'A → B' : 'B → A'}: {counts.packets} / {counts.bytes}</div>)}</td>
          {metrics.map(([key]) => <td key={key}><CompactEvidence value={flow.metrics[key] ?? t('Not observed / unavailable', '관찰되지 않음 / 사용 불가')}/></td>)}
          <td>{flow.confidence !== undefined && <CompactEvidence value={flow.confidence}/>}<p>{t('Observation confidence, not a path diagnosis.', '관찰의 신뢰도이며 경로 진단이 아닙니다.')}</p>{flow.warnings.map((warning, i) => <p className="warning" key={i}>{warningLabel(language, warning, true)}</p>)}<details><summary>{t('Metric evidence', '측정 증거')}</summary><CompactEvidence value={flow.metrics}/>{flow.findings !== undefined && <CompactEvidence value={flow.findings}/>} {flow.evidence !== undefined && <CompactEvidence value={flow.evidence}/>}</details></td>
        </tr>)}
      </tbody></table></div>
      <div className="actions"><button className="secondary" disabled={current === 0} onClick={() => setPage(current - 1)}>{t('Previous flows', '이전 흐름')}</button><span>{t('Page', '페이지')} {current + 1} / {pages} · {report.flows.length} {t('retained flows', '개 보존된 흐름')}</span><button className="secondary" disabled={current + 1 >= pages} onClick={() => setPage(current + 1)}>{t('Next flows', '다음 흐름')}</button></div>
    </>}
  </section>;
}
