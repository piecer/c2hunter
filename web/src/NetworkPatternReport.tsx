import { useState } from 'react';

// network-pattern-report-v1: producer-owned contract in c2hunter_analysis.network_report.
type Endpoint = { ip: string; port: number | null };
export type PatternIssue = {
  id: string; pattern: string; title: string; severity: string;
  scope: { sensor_id: string; interface_id: number | null; protocol: string; peer: Endpoint };
  event_count: number; affected_flow_count: number; affected_host_count: number;
  first_seen: string; last_seen: string;
  examples: { endpoint_a: Endpoint; endpoint_b: Endpoint; event_count: number; facts?: Record<string, number> }[];
  omitted_examples: number; evidence: string[]; uncertainty: string[]; next_checks: string[];
};
export type PatternReport = {
  version: string;
  summary: Record<string, unknown>;
  issues?: PatternIssue[];
  warnings: string[]; limitations: string[];
};
const labels: Record<string, string> = {
  syn_retransmissions: 'SYN retransmissions', matched_resets: 'Matched resets',
  data_retransmissions: 'Data retransmissions', duplicate_acks: 'Duplicate ACKs',
  icmp_errors: 'ICMP errors', udp_duplicate_candidates: 'UDP duplicate candidates',
};
const warningLabels: Record<string, string> = {
  ICMP_QUOTE_LIMIT_REACHED: 'The ICMP quotation matching budget was reached; additional relationships may be unobserved.',
  OBSERVATION_LIMIT_REACHED: 'The observation tracking budget was reached; additional patterns may be unobserved.',
  FLOW_TRACKING_LIMIT_REACHED: 'The flow tracking budget was reached; some traffic was not correlated.',
  CORRELATION_LIMIT_REACHED: 'The packet correlation budget was reached; additional patterns may be unobserved.',
  INCOMPLETE_RECORDS: 'Invalid or unsupported records were skipped.',
  INCOMPLETE_PACKET_EVIDENCE: 'Packet-level evidence was incomplete.',
  NON_MONOTONIC_TIMESTAMPS: 'Timestamps were out of order; correlation was interrupted.',
  INCOMPLETE_ICMP_QUOTE: 'An ICMP quotation could not fully identify the original traffic.',
  ONE_DIRECTION_OBSERVED: 'Some flows were visible in only one direction.',
};
const summaryCounts = ['scanned_records', 'evaluated_records', 'skipped_records', 'incomplete_records', 'flow_count', 'suspect_flow_count', 'detailed_flow_count', 'issue_count', 'displayed_issue_count', 'omitted_issue_count'];
const text = (value: unknown, max = 320) => typeof value === 'string' ? value.slice(0, max) + (value.length > max ? '… [text truncated]' : '') : 'Not reported';
const count = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
const number = (value: unknown) => count(value)?.toLocaleString() ?? 'Unknown';
const endpoint = (value?: Endpoint) => value && typeof value.ip === 'string' ? `${value.ip.includes(':') ? `[${text(value.ip, 80)}]` : text(value.ip, 80)}${value.port == null ? '' : `:${count(value.port) ?? 'unknown'}`}` : 'Endpoint not reported';
function Notes({ values }: { values: unknown }) {
  const items = Array.isArray(values) ? values : [];
  return <ul>{items.slice(0, 4).map((value, index) => <li key={index}>{text(value)}</li>)}{items.length > 4 && <li>{items.length - 4} additional notes omitted from this view.</li>}</ul>;
}
export default function NetworkPatternReport({ report }: { report: PatternReport }) {
  const [expanded, setExpanded] = useState<{ report: PatternReport; index: number }>();
  const summary = report.summary ?? {};
  const issues = Array.isArray(report.issues) ? report.issues : [];
  const verdict = summary.verdict;
  const warnings = Array.isArray(report.warnings) ? report.warnings : [];
  const recognized = Array.isArray(report.issues) && Array.isArray(report.warnings) && summaryCounts.every(key => count(summary[key]) !== undefined) && warnings.every(warning => Object.hasOwn(warningLabels, warning)) && issues.every(issue => issue && Object.hasOwn(labels, issue.pattern));
  const complete = recognized && warnings.length === 0 && summary.coverage_complete === true && summary.skipped_records === 0 && summary.incomplete_records === 0 && (count(summary.evaluated_records) ?? 0) > 0;
  const safeClear = complete && summary.issue_count === 0 && issues.length === 0 && summary.omitted_issue_count === 0 && summary.truncated === false;
  const heading = recognized && verdict === 'anomaly_observed' ? 'Anomaly observed' : recognized && verdict === 'no_clear_anomaly' && safeClear ? 'No clear anomaly observed' : 'Insufficient data';
  return <section className="panel network-report" aria-labelledby="overall-network-heading">
    <p className="eyebrow">OVERALL NETWORK REPORT</p><h2 id="overall-network-heading">{heading}</h2>
    <p>{!recognized || (verdict === 'no_clear_anomaly' && !safeClear) ? 'Report fields are incomplete, unsupported or inconsistent; an overall conclusion cannot be confirmed.' : text(summary.narrative)}</p>
    <p className="muted">Pattern scan → detailed analysis of identified patterns → one overall report. These are analysis stages, not live stage progress.</p>
    <p>Transport observations are not C2 classifications. Shared patterns do not prove a shared root cause. Single-vantage evidence cannot prove path loss or a fault location.</p>
    <p className="warning">RTT/latency, interarrival dispersion and TTL measurements are not computed by this pattern-first producer. Latency analysis is unsupported in new reports; existing saved legacy reports retain their original measurements behind the legacy toggle.</p>
    <section aria-label="Analysis coverage"><h3>Coverage and omissions</h3>
      <p className={complete ? '' : 'warning'}>{complete ? 'Coverage complete for evaluated evidence; this is not proof of a healthy network.' : 'Incomplete or unknown coverage — absence of findings cannot establish a healthy network.'}</p>
      <p>{number(summary.scanned_records)} records scanned · {number(summary.evaluated_records)} evaluated · {number(summary.skipped_records)} skipped · {number(summary.incomplete_records)} incomplete</p>
      {summary.counts_are_lower_bounds === true && <p className="warning">Counts are lower bounds, not complete capture totals. {number(summary.tracking_limited_records)} records exceeded tracking limits; retained observations remain valid, but additional anomalies may be missing.</p>}
      <p>{number(summary.flow_count)} flows scanned · {number(summary.suspect_flow_count)} suspect flows · {number(summary.detailed_flow_count)} representative flows analyzed in detail</p>
      <p>{number(summary.issue_count)} issue groups · {Math.min(issues.length, 8)} shown · {number(summary.omitted_issue_count)} groups omitted by producer · {Math.max(0, issues.length - 8)} additional groups omitted from this view</p>
      {summary.truncated === true && <p className="warning">Report truncated: not all issue groups are included. Detection counts are not a complete list of displayed evidence.</p>}
      <ul>{warnings.slice(0, 8).map((warning, index) => <li key={index}>{Object.hasOwn(warningLabels, warning) ? `${warningLabels[warning]} (${warning})` : 'Unsupported coverage warning — report interpretation unavailable.'}</li>)}{warnings.length > 8 && <li>{warnings.length - 8} additional coverage warnings omitted from this view.</li>}</ul><Notes values={report.limitations}/>
    </section>
    <h3>Grouped observations</h3>
    {!issues.length && <p>No grouped observations retained. Consult coverage before interpreting this result.</p>}
    {recognized && issues.slice(0, 8).map((issue, index) => {
      const open = expanded?.report === report && expanded.index === index;
      const examples = Array.isArray(issue.examples) ? issue.examples : [];
      return <article className="panel compact" key={index}>
        <h4>{labels[issue.pattern] ?? 'Unsupported observation pattern'}</h4>
        <p>{number(issue.event_count)} events · {number(issue.affected_flow_count)} affected flows · {number(issue.affected_host_count)} affected hosts</p>
        <p>Affected range: {text(issue.scope?.sensor_id, 80)} · interface {issue.scope?.interface_id == null ? 'unknown' : number(issue.scope.interface_id)} · {text(issue.scope?.protocol, 12)} · peer {endpoint(issue.scope?.peer)}</p>
        <p>Observed time: {text(issue.first_seen, 40)} → {text(issue.last_seen, 40)}</p>
        <h5>Representative proof</h5><Notes values={issue.evidence}/>
        <h5>Uncertainty</h5><Notes values={issue.uncertainty}/>
        <h5>Next checks</h5><Notes values={issue.next_checks}/>
        <button className="secondary" aria-expanded={open} aria-controls={`network-evidence-${index}`} onClick={() => setExpanded(open ? undefined : { report, index })}>{open ? 'Hide' : 'Show'} representative evidence — {labels[issue.pattern] ?? 'unknown pattern'}</button>
        {open && <section id={`network-evidence-${index}`} aria-label="Representative flow evidence">
          {!examples.length && <p>No representative flow examples were included.</p>}
          <ul>{examples.slice(0, 3).map((example, i) => <li key={i}>{endpoint(example.endpoint_a)} ↔ {endpoint(example.endpoint_b)} · {number(example.event_count)} events<ul>{Object.entries(example.facts ?? {}).slice(0, 8).map(([key, value]) => <li key={key}>{text(key, 64)}: {typeof value === 'number' && Number.isFinite(value) ? String(value) : 'Unknown'}</li>)}{Object.keys(example.facts ?? {}).length > 8 && <li>{Object.keys(example.facts ?? {}).length - 8} additional facts omitted from this view.</li>}</ul></li>)}</ul>
          <p>{number(issue.omitted_examples)} examples omitted by producer · {Math.max(0, examples.length - 3)} additional examples omitted from this view. Only retained evidence is available here; no additional data is fetched.</p>
        </section>}
      </article>;
    })}
  </section>;
}
