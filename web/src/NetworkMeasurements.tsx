import { useReportLanguage } from './reportLanguageContext';
import { choose, measurementQualityReasons, measurementQualityStatuses } from './reportTranslations';
import { parseMeasurementQuality, type MetricQuality } from './networkMeasurementQuality';

const object = (value: unknown): Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
const causes: Record<string, [string, string]> = {
  response_visibility_or_filtering: ['Missing response visibility, filtering or duplicate capture may explain repeated connection attempts.', '응답 관찰 누락, 필터링 또는 중복 캡처가 반복 연결 시도를 설명할 수 있습니다.'],
  service_refusal_or_policy: ['Service refusal or policy may explain the matched reset.', '서비스 거부 또는 정책이 일치하는 연결 초기화를 설명할 수 있습니다.'],
  loss_reordering_or_capture_duplication: ['Loss, reordering or duplicate capture may explain the repeated TCP observations.', '손실, 순서 변경 또는 중복 캡처가 반복 TCP 관찰을 설명할 수 있습니다.'],
  application_repeat_or_capture_duplication: ['Application repeats or duplicate capture may explain repeated UDP payloads.', '애플리케이션 반복 또는 중복 캡처가 반복 UDP 페이로드를 설명할 수 있습니다.'],
  reported_network_or_policy_error: ['A reported network or policy error may explain the ICMP observation.', '보고된 네트워크 또는 정책 오류가 ICMP 관찰을 설명할 수 있습니다.'],
};
const reasons: Record<string, [string, string]> = {
  INCOMPLETE_PACKET_EVIDENCE: ['Packet metadata is incomplete.', '패킷 메타데이터가 불완전합니다.'],
  NON_MONOTONIC_TIMESTAMPS: ['Timestamps are out of order.', '타임스탬프 순서가 뒤섞였습니다.'],
  CORRELATION_LIMIT_REACHED: ['Correlation tracking limit reached.', '연관 추적 한도에 도달했습니다.'],
  MISSING_TTL: ['TTL / Hop Limit metadata is missing.', 'TTL / 홉 제한 메타데이터가 없습니다.'],
  NO_UNAMBIGUOUS_RTT: ['No unambiguous RTT sample is available.', '모호하지 않은 RTT 표본이 없습니다.'],
  NOT_TCP: ['TCP RTT is not applicable to this protocol.', '이 프로토콜에는 TCP RTT가 적용되지 않습니다.'],
  ONE_DIRECTION_OBSERVED: ['Only one direction was observed.', '한 방향만 관찰되었습니다.'],
};
export function CauseHypothesis({ value, leading = false }: { value: unknown; leading?: boolean }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => choose(language, en, ko);
  const cause = object(value);
  const pair = typeof cause.code === 'string' && Object.hasOwn(causes, cause.code) ? causes[cause.code] : undefined;
  return <>{leading ? <h3>{t('Leading possible cause — hypothesis', '주요 가능한 원인 — 가설')}</h3> : <h5>{t('Possible cause — hypothesis', '가능한 원인 — 가설')}</h5>}<p>{pair && cause.confidence === 'low' ? choose(language, ...pair) : t('Unknown — no supported cause hypothesis was reported.', '알 수 없음 — 지원되는 원인 가설이 보고되지 않았습니다.')}</p>{pair && cause.confidence === 'low' && <p className="muted">{t('Low causal confidence. Compare the pattern evidence and representative measurements below; these are alternatives, not a confirmed diagnosis.', '원인에 대한 신뢰도는 낮습니다. 아래 패턴 증거와 대표 측정값을 비교하세요. 이는 대안적 설명이며 확정 진단이 아닙니다.')}</p>}</>;
}
export default function NetworkMeasurements({ value }: { value: unknown }) {
  const language = useReportLanguage();
  const t = (en: string, ko: string) => choose(language, en, ko);
  const m = object(value);
  const parsedQuality = parseMeasurementQuality(m);
  if (parsedQuality === 'invalid') return <section aria-label={t('Supporting measurements', '보조 측정값')}><p>{t('Invalid measurement qualification — evidence cannot be qualified.', '잘못된 측정 적절성 정보 — 증거의 적절성을 판단할 수 없습니다.')}</p></section>;
  const q = parsedQuality === 'not_provided' ? undefined : parsedQuality;
  const local = (pair: readonly [string, string]) => choose(language, pair[0], pair[1]);
  const quality = (v: MetricQuality | undefined) => v ? ` · ${local(measurementQualityStatuses[v.status])}. ${v.reasons.map(code => local(measurementQualityReasons[code])).join(' ')}` : '';
  const number = (v: unknown) => typeof v === 'number' && Number.isFinite(v) && v >= 0 ? String(v) : t('Unknown', '알 수 없음');
  const count = (v: unknown) => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? String(v) : t('Unknown', '알 수 없음');
  const stats = (v: unknown) => {
    const s = object(v);
    const measured = typeof s.count === 'number' && Number.isSafeInteger(s.count) && s.count > 0;
    const singleton = s.count === 1 && s.stddev === 0 ? t(' · Raw singleton stddev: 0; not meaningful evidence of dispersion or stability.', ' · 단일 표본 원시 표준편차: 0; 산포 또는 안정성에 대한 유의미한 증거가 아닙니다.') : '';
    return `${t('Samples', '표본')}: ${count(s.count)} · ${t('mean / min / max', '평균 / 최소 / 최대')}: ${[s.mean, s.min, s.max].map(n => number(measured ? n : null)).join(' / ')} · ${t('dispersion (population stddev)', '산포 (모집단 표준편차)')}: ${number(measured && (s.count as number) > 1 ? s.stddev : null)}${singleton}`;
  };
  const sources = object(m.rtt_sources);
  const excluded = object(m.rtt_excluded);
  const spacing = object(m.interarrival_variation_ms);
  const ttl = object(m.ttl_observed);
  const reasonList = Array.isArray(m.reasons) ? m.reasons : [];
  return <section aria-label={t('Supporting measurements', '보조 측정값')}>
    <h5>{t('Detailed measurement analysis', '측정값 상세 분석')}</h5>
    <p className="muted">{t('Representative flow only, not pooled issue-group statistics. Unknown means missing or ineligible evidence, never a measured zero.', '대표 흐름만의 값이며 문제 그룹 전체의 통계가 아닙니다. 알 수 없음은 증거 누락 또는 부적격을 뜻하며 측정된 0이 아닙니다.')}</p>
    <p>{t('Measurement coverage', '측정 범위')}: {m.coverage_complete === true ? t('Complete', '완전') : t('Incomplete / unknown', '불완전 / 알 수 없음')} · {m.status === 'observed' ? t('Observed', '관찰됨') : m.status === 'unsupported' ? t('Unsupported', '지원 안 됨') : t('Insufficient evidence', '증거 부족')}</p>
    <p className="muted">{t('Coverage describes tracking and evidence gaps, not sample adequacy. At every sample count, representativeness not established; observed samples never imply normality or statistical confidence.', '측정 범위는 추적 및 증거 공백을 설명하며 표본 적절성을 뜻하지 않습니다. 표본 수에 관계없이 대표성은 확립되지 않음 — 관찰된 표본은 정상 또는 통계적 신뢰도를 뜻하지 않습니다.')}</p>
    {!q && <p>{t('Sample qualification: Not provided. Do not infer sufficient evidence from coverage or zero dispersion.', '표본 적절성: 제공되지 않음. 측정 범위나 산포 0에서 충분한 증거를 추론하지 마세요.')}</p>}
    <p><strong>{t('Observed RTT (ms)', '관찰된 RTT (ms)')}</strong> — {stats(m.observed_rtt_ms)}{quality(q?.observed_rtt_ms)}</p>
    <p>{t('Eligible RTT samples', '적격 RTT 표본')}: SYN/ACK {count(sources.syn_ack)} · {t('Data/ACK', '데이터/ACK')} {count(sources.data_ack)}. {t('Excluded candidate matches', '제외된 후보 일치')}: {t('ambiguous / retransmitted', '모호함 / 재전송')} {count(excluded.ambiguous)} · {t('nonpositive time', '0 이하 시간')} {count(excluded.nonpositive_time)} · {t('nonexact ACK', '정확히 일치하지 않는 ACK')} {count(excluded.nonexact_ack)}.</p>
    <p className="muted">{t('Capture-local response timing includes peer delay; it is not one-way latency or host end-to-end RTT. Retransmission ambiguity excludes RTT candidates; no high-latency diagnosis without a baseline.', '캡처 지점의 응답 시간에는 상대 지연이 포함되며 단방향 지연이나 호스트 간 종단 RTT가 아닙니다. 재전송으로 모호한 RTT 후보는 제외되며 기준값 없이 높은 지연으로 진단하지 않습니다.')}</p>
    <p><strong>{t('Interarrival dispersion (ms)', '도착 간격 산포 (ms)')}</strong><br/>A → B: {stats(spacing.a_to_b)}{quality(q?.interarrival_variation_ms.a_to_b)}<br/>B → A: {stats(spacing.b_to_a)}{quality(q?.interarrival_variation_ms.b_to_a)}</p>
    <p className="muted">{t('Same-direction capture packet spacing, not network jitter. Application pacing, queueing and capture effects remain possible.', '같은 방향에서 캡처된 패킷의 도착 간격이며 네트워크 지터가 아닙니다. 애플리케이션 전송 간격, 큐 대기 및 캡처 영향의 가능성이 남아 있습니다.')}</p>
    <p><strong>{t('IPv4 TTL / IPv6 Hop Limit', 'IPv4 TTL / IPv6 홉 제한')}</strong>{(['a_to_b', 'b_to_a'] as const).map((direction, i) => {
      const s = object(ttl[direction]);
      const measured = typeof s.count === 'number' && s.count > 0;
      return <span key={direction}><br/>{i === 0 ? 'A → B' : 'B → A'}: {t('Samples', '표본')} {count(s.count)} · {t('min / max', '최소 / 최대')} {number(measured ? s.min : null)} / {number(measured ? s.max : null)} · {t('changes', '변화')} {count(s.changes)} · {t('missing', '누락')} {count(s.missing)}{quality(q?.ttl_observed[direction])}</span>;
    })}</p>
    <p className="muted">{t('TTL / Hop Limit variation is not proof of route changes, exact hop count or asymmetric routing.', 'TTL / 홉 제한 변화는 경로 변경, 정확한 홉 수 또는 비대칭 라우팅의 증거가 아닙니다.')}</p>
    {reasonList.length > 0 && <p>{reasonList.slice(0, 7).map(code => typeof code === 'string' && Object.hasOwn(reasons, code) ? `${choose(language, ...reasons[code])} (${code})` : t('Unsupported measurement reason.', '지원되지 않는 측정 사유입니다.')).join(' ')}{reasonList.length > 7 && t(' Additional reasons omitted.', ' 추가 사유 생략.')}</p>}
  </section>;
}
