import { useState } from 'react';
import { StructuredValue } from './AnalysisConfiguration';
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
  return <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', minWidth: 100, maxWidth: 280, maxHeight: 280, overflow: 'auto', fontSize: '0.75rem' }}>{typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}</pre>;
}

export default function NetworkAnomalyPanel({ report }: { report?: NetworkAnomalyReport }) {
  const [legacy, setLegacy] = useState<NetworkAnomalyReport>();
  if (!report) return <section className="panel"><h2>Overall network report</h2><p role="status">No network report is available yet. Check job status and errors.</p></section>;
  if (report.version === 'network-pattern-report-v1') return <NetworkPatternReport report={report}/>;
  return <section className="panel"><h2>Legacy report</h2><p>An overall verdict is unavailable for this saved report. Re-run analysis to produce a pattern-first report.</p><button className="secondary" aria-expanded={legacy === report} onClick={() => setLegacy(legacy === report ? undefined : report)}>{legacy === report ? 'Hide' : 'Show'} legacy flow observations</button>{legacy === report && <LegacyNetworkObservations report={report}/>}</section>;
}

function LegacyNetworkObservations({ report }: { report: NetworkAnomalyReport }) {
  const [page, setPage] = useState(0);
  if (!report) return <section className="panel"><h2>Network observations</h2><p role="status">No network report is available yet. Check job status and errors.</p></section>;
  const pages = Math.max(1, Math.ceil(report.flows.length / 25));
  const current = Math.min(page, pages - 1);
  return <section className="panel" aria-labelledby="network-observations-heading">
    <p className="eyebrow">NETWORK ANOMALY · {report.version}</p><h2 id="network-observations-heading">Network observations</h2>
    <p>Transport observations are not C2 classifications. Single-vantage evidence cannot prove path loss, asymmetric routing, or a fault location.</p>
    <details open><summary>Capture confidence and limitations</summary><ul>{report.limitations.map((text, index) => <li key={index}>{text}</li>)}</ul><StructuredValue value={report.summary}/></details>
    {report.warnings.map((warning, index) => <p className="warning" key={index}>{warning}</p>)}
    {!report.flows.length ? <p>No supported flows observed; this is not evidence of a healthy path.</p> : <>
      <div className="table-wrap"><table aria-label="Bidirectional network flows"><thead><tr><th>Flow A ↔ B</th><th>Observation point</th><th>Packets / bytes by direction</th>{metrics.map(([, label]) => <th key={label}>{label}</th>)}<th>Evidence / confidence / warnings</th></tr></thead><tbody>
        {report.flows.slice(current * 25, current * 25 + 25).map((flow, index) => <tr key={index}>
          <td><strong>{endpoint(flow.endpoint_a)}</strong><small>↔ {endpoint(flow.endpoint_b)}</small>{flow.protocol}</td>
          <td>{flow.sensor_id}<small>Interface {flow.interface_id ?? 'unknown'}</small></td>
          <td>{Object.entries(flow.observed_directions).map(([direction, counts]) => <div key={direction}>{direction === 'a_to_b' ? 'A → B' : 'B → A'}: {counts.packets} / {counts.bytes}</div>)}</td>
          {metrics.map(([key]) => <td key={key}><CompactEvidence value={flow.metrics[key] ?? 'Not observed / unavailable'}/></td>)}
          <td>{flow.confidence !== undefined && <CompactEvidence value={flow.confidence}/>}<p>Observation confidence, not a path diagnosis.</p>{flow.warnings.map((warning, i) => <p className="warning" key={i}>{warning}</p>)}<details><summary>Metric evidence</summary><CompactEvidence value={flow.metrics}/>{flow.findings !== undefined && <CompactEvidence value={flow.findings}/>} {flow.evidence !== undefined && <CompactEvidence value={flow.evidence}/>}</details></td>
        </tr>)}
      </tbody></table></div>
      <div className="actions"><button className="secondary" disabled={current === 0} onClick={() => setPage(current - 1)}>Previous flows</button><span>Page {current + 1} of {pages} · {report.flows.length} retained flows</span><button className="secondary" disabled={current + 1 >= pages} onClick={() => setPage(current + 1)}>Next flows</button></div>
    </>}
  </section>;
}
