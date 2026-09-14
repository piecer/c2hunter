import type { ReportLanguage } from './reportLanguageContext';

// Stable producer codes. English v1 prose is also checked exactly before translation:
// saved reports have no reason codes, and changed/unknown prose must remain visible.
export const patterns: Record<string, [string, string]> = {
  syn_retransmissions: ['SYN retransmissions', 'SYN 재전송'],
  matched_resets: ['Matched resets', 'SYN 시도와 일치하는 연결 초기화'],
  data_retransmissions: ['Data retransmissions', '데이터 재전송'],
  duplicate_acks: ['Duplicate ACKs', '중복 ACK'],
  icmp_errors: ['ICMP errors', 'ICMP 오류'],
  udp_duplicate_candidates: ['UDP duplicate candidates', 'UDP 중복 후보'],
};
export const warnings: Record<string, [string, string]> = {
  ICMP_QUOTE_LIMIT_REACHED: ['The ICMP quotation matching budget was reached; additional relationships may be unobserved.', 'ICMP 인용 패킷 연결 한도에 도달하여 추가 연관 관계가 관찰되지 않았을 수 있습니다.'],
  OBSERVATION_LIMIT_REACHED: ['The observation tracking budget was reached; additional patterns may be unobserved.', '관찰 추적 한도에 도달하여 추가 패턴이 관찰되지 않았을 수 있습니다.'],
  FLOW_TRACKING_LIMIT_REACHED: ['The flow tracking budget was reached; some traffic was not correlated.', '흐름 추적 한도에 도달하여 일부 트래픽의 연관 관계를 분석하지 못했습니다.'],
  CORRELATION_LIMIT_REACHED: ['The packet correlation budget was reached; additional patterns may be unobserved.', '패킷 연관 분석 한도에 도달하여 추가 패턴이 관찰되지 않았을 수 있습니다.'],
  INCOMPLETE_RECORDS: ['Invalid or unsupported records were skipped.', '잘못되었거나 지원하지 않는 레코드를 건너뛰었습니다.'],
  INCOMPLETE_PACKET_EVIDENCE: ['Packet-level evidence was incomplete.', '패킷 수준 증거가 불완전합니다.'],
  NON_MONOTONIC_TIMESTAMPS: ['Timestamps were out of order; correlation was interrupted.', '타임스탬프 순서가 뒤섞여 연관 분석이 중단되었습니다.'],
  INCOMPLETE_ICMP_QUOTE: ['An ICMP quotation could not fully identify the original traffic.', 'ICMP 인용 패킷으로 원래 트래픽을 완전히 식별하지 못했습니다.'],
  ONE_DIRECTION_OBSERVED: ['Some flows were visible in only one direction.', '일부 흐름은 한 방향에서만 관찰되었습니다.'],
};
const legacyWarnings: Record<string, [string, string]> = {
  FLOW_STATE_LIMIT_REACHED: ['The per-flow correlation state tracking limit was reached; additional transport patterns in this flow were not evaluated.', '흐름별 연관 분석 상태 추적 한도에 도달하여 해당 흐름의 추가 전송 패턴을 평가하지 못했습니다.'],
  PACKET_LIMIT_REACHED: ['Packet processing limit reached.', '패킷 처리 한도에 도달했습니다.'],
  FLOW_LIMIT_REACHED: ['Flow processing limit reached.', '흐름 처리 한도에 도달했습니다.'],
};
export const diagnostics: Record<string, [string, string][]> = {
  syn_retransmissions: [
    ['The same directional SYN sequence was observed again before a matching response.', '일치하는 응답이 오기 전에 같은 방향의 동일한 SYN 순서 번호가 다시 관찰되었습니다.'],
    ['Repeated attempts do not distinguish a missing response from duplicate capture.', '반복 시도만으로는 응답 누락과 중복 캡처를 구분할 수 없습니다.'],
    ['Inspect handshake response visibility, listener state and firewall logs.', '연결 수립 응답의 관찰 여부, 수신 대기 상태 및 방화벽 로그를 확인하세요.'],
  ],
  matched_resets: [
    ['A reverse RST+ACK acknowledgment matched an observed SYN sequence plus one.', '반대 방향 RST+ACK의 확인 번호가 관찰된 SYN 순서 번호에 1을 더한 값과 일치했습니다.'],
    ['A matched reset suggests refusal of this attempt, not proof of a host outage.', '일치하는 연결 초기화는 해당 시도의 거부를 시사하지만 호스트 장애를 입증하지는 않습니다.'],
    ['Check listener availability, service policy and reset-origin logs.', '수신 대기 서비스의 가용성, 서비스 정책 및 연결 초기화 발생 지점의 로그를 확인하세요.'],
  ],
  data_retransmissions: [
    ['TCP sequence, payload length and payload hash repeated in the same direction.', '같은 방향에서 TCP 순서 번호, 페이로드 길이 및 페이로드 해시가 반복되었습니다.'],
    ['Exact repeats do not prove path loss; capture duplication remains possible.', '완전히 동일한 반복이 경로 손실을 입증하지는 않으며 중복 캡처 가능성이 남아 있습니다.'],
    ['Compare sequence/ACK progress with peer captures and retransmission counters.', '순서 번호 및 ACK 진행 상황을 상대측 캡처와 재전송 카운터에 비교하세요.'],
  ],
  duplicate_acks: [
    ['Repeated pure ACK sequence/acknowledgment/window signatures accompanied outstanding data.', '미확인 데이터가 있는 상태에서 순수 ACK의 순서 번호·확인 번호·윈도 크기 조합이 반복되었습니다.'],
    ['Reordering and duplicated capture can also produce duplicate ACK observations.', '패킷 순서 변경과 중복 캡처로도 중복 ACK가 관찰될 수 있습니다.'],
    ['Inspect missing sequence ranges, reordering and subsequent ACK progress.', '누락된 순서 번호 범위, 순서 변경 및 이후 ACK 진행 상황을 확인하세요.'],
  ],
  udp_duplicate_candidates: [
    ['Directional UDP payload hash and length repeated within a capture-local flow epoch.', '캡처 내 동일 흐름 추적 구간에서 같은 방향의 UDP 페이로드 해시와 길이가 반복되었습니다.'],
    ['Application retries or intentional repeats are not UDP transport retransmissions.', '애플리케이션 재시도나 의도적인 반복은 UDP 전송 계층의 재전송이 아닙니다.'],
    ['Inspect application request identifiers and expected retry/heartbeat behavior.', '애플리케이션 요청 식별자와 예상되는 재시도·상태 확인 동작을 확인하세요.'],
  ],
  icmp_errors: [
    ['ICMP errors were observed; valid quoted endpoints scope the affected peer when present.', 'ICMP 오류가 관찰되었습니다. 유효한 인용 패킷의 종단점이 있으면 이를 통해 영향받은 상대를 특정합니다.'],
    ['An ICMP report is not proof of permanent unreachability or a common root cause.', 'ICMP 보고만으로 영구적인 도달 불가 상태나 공통 근본 원인을 입증할 수 없습니다.'],
    ['Inspect original ICMP type/code, quoted headers and reporting-device policy.', '원본 ICMP 유형·코드, 인용된 헤더 및 보고 장치의 정책을 확인하세요.'],
  ],
};
const prose: Record<string, string> = Object.fromEntries([
  ...Object.values(diagnostics).flat(),
  ['Supported observable patterns identified; inspect grouped evidence.', '지원되는 관찰 패턴이 식별되었습니다. 그룹별 증거를 확인하세요.'],
  ['Supported observable patterns identified; inspect grouped evidence. Coverage is incomplete; additional patterns may be unobservable.', '지원되는 관찰 패턴이 식별되었습니다. 그룹별 증거를 확인하세요. 분석 범위가 불완전하여 추가 패턴이 관찰되지 않았을 수 있습니다.'],
  ['No supported anomaly pattern observed.', '지원되는 이상 패턴이 관찰되지 않았습니다.'],
  ['Evidence is insufficient to exclude anomaly patterns.', '이상 패턴의 가능성을 배제하기에는 증거가 부족합니다.'],
  ['Shared peer and pattern do not establish a shared root cause.', '상대와 패턴이 같다는 사실만으로 공통 근본 원인을 확정할 수 없습니다.'],
  ['Check capture completeness and duplicate capture.', '캡처의 완전성과 중복 캡처 여부를 확인하세요.'],
  ['Single-vantage observations do not prove loss, asymmetric routing or root cause.', '단일 관찰 지점의 증거로는 손실, 비대칭 라우팅 또는 근본 원인을 입증할 수 없습니다.'],
  ['Duplicate capture can mimic TCP retransmissions and UDP duplicate candidates.', '중복 캡처가 TCP 재전송 및 UDP 중복 후보처럼 보일 수 있습니다.'],
  ['RTT and interarrival dispersion are not classified without a configured baseline.', '기준값을 설정하지 않으면 RTT 및 패킷 도착 간격의 산포를 분류하지 않습니다.'],
  ['Single-vantage observations do not prove loss or asymmetric routing.', '단일 관찰 지점의 증거로는 손실이나 비대칭 라우팅을 입증할 수 없습니다.'],
  ['Duplicate capture can mimic retransmissions.', '중복 캡처가 재전송처럼 보일 수 있습니다.'],
  ['Observed RTT includes peer response delay; not host end-to-end RTT.', '관찰된 RTT에는 상대의 응답 지연이 포함되며 호스트 간 종단 RTT가 아닙니다.'],
  ['Interarrival variation is not one-way jitter.', '패킷 도착 간격의 변동은 단방향 지터가 아닙니다.'],
  ['Capture-local RTT includes peer ACK delay; it is not one-way latency.', '캡처 지점의 RTT에는 상대 ACK 지연이 포함되며 단방향 지연이 아닙니다.'],
  ['Interarrival dispersion is not proof of network jitter or congestion.', '도착 간격 산포는 네트워크 지터나 혼잡의 증거가 아닙니다.'],
  ['Outer TTL/hop-limit variation does not prove path changes or exact hop counts.', '외부 TTL/홉 제한 변화는 경로 변경이나 정확한 홉 수를 입증하지 않습니다.'],
  ['Measurements describe bounded representative flows, not pooled issue populations.', '측정값은 한도 내의 대표 흐름을 설명하며 문제 그룹 전체를 합산한 값이 아닙니다.'],
  ['UDP duplicates are candidates, not transport retransmissions.', 'UDP 중복은 후보이며 전송 계층의 재전송이 아닙니다.'],
]);
export const measurementQualityStatuses = {
  unavailable: ['Unavailable', '사용 불가'],
  limited_samples: ['Limited samples', '제한된 표본'],
  observed_samples: ['Observed samples', '관찰된 표본'],
} as const;
export const measurementQualityReasons = {
  NO_SAMPLES: ['No eligible samples.', '적격 표본이 없습니다.'],
  SINGLE_SAMPLE: ['One sample cannot establish dispersion, stability or path characteristics.', '표본 하나로 산포, 안정성 또는 경로 특성을 확립할 수 없습니다.'],
  HANDSHAKE_ONLY: ['Handshake-only RTT; no eligible data/ACK RTT samples.', '핸드셰이크만의 RTT이며 적격 데이터/ACK RTT 표본은 없습니다.'],
  BIDIRECTIONAL_RTT_NOT_ESTABLISHED: ['Bidirectional RTT samples not established; RTT sample directions are not tracked.', '양방향 RTT 표본은 확립되지 않음 — RTT 표본 방향을 추적하지 않습니다.'],
  SELECTION_BIAS_POSSIBLE: ['Selection bias possible: exclusions, missing metadata or tracking gaps can affect the retained samples.', '선택 편향 가능: 제외, 메타데이터 누락 또는 추적 공백이 남은 표본에 영향을 줄 수 있습니다.'],
} as const;
export const factLabels: Record<string, string> = {
  metric_quality: '측정별 표본 적절성',
  rtt_sources: 'RTT 표본 출처', syn_ack: 'SYN/ACK 표본', data_ack: '데이터/ACK 표본', rtt_excluded: '제외된 RTT 후보 일치', ambiguous: '모호함 / 재전송', nonpositive_time: '0 이하 시간', nonexact_ack: '정확히 일치하지 않는 ACK', coverage_complete: '분석 범위 완전 여부', status: '상태', reasons: '측정 사유', changes: '변화 횟수', missing: '누락 수',
  tcp_sequence: 'TCP 순서 번호', tcp_acknowledgment: 'TCP 확인 번호', tcp_window: 'TCP 윈도 크기', transport_payload_length: '전송 페이로드 길이', icmp_type: 'ICMP 유형', icmp_code: 'ICMP 코드',
  matched_resets: 'SYN 시도와 일치하는 연결 초기화', syn_retransmissions: 'SYN 재전송', data_retransmissions: '데이터 재전송', duplicate_acks: '중복 ACK', observed_rtt_ms: '관찰된 RTT (ms)', interarrival_variation_ms: '도착 간격 변동 (ms)', udp_duplicate_candidates: 'UDP 중복 후보', icmp_errors: 'ICMP 오류',
  scanned_records: '검사한 레코드', skipped_records: '건너뛴 레코드', flow_count: '흐름 수', truncated: '일부 생략됨',
  count: '개수', min: '최솟값', max: '최댓값', mean: '평균', median: '중앙값', p95: '95백분위수', stddev: '표준편차', a_to_b: 'A → B', b_to_a: 'B → A', ttl_observed: '관찰된 TTL', icmp_error_details: 'ICMP 오류 상세', type: '유형', code: '코드', reporter_ip: '보고 장치 IP', quoted_flow: '인용된 흐름', source_ip: '출발지 IP', destination_ip: '목적지 IP', source_port: '출발지 포트', destination_port: '목적지 포트', protocol: '프로토콜', rst_count: 'RST 수', syn_count: 'SYN 수',
};
export const choose = (language: ReportLanguage, en: string, ko: string) => language === 'ko' ? ko : en;
export function rawText(language: ReportLanguage, value: unknown, max = 320): string {
  if (typeof value !== 'string') return choose(language, 'Not reported', '보고되지 않음');
  return value.slice(0, max) + (value.length > max ? choose(language, '… [text truncated]', '… [텍스트 생략]') : '');
}
export function translateProse(language: ReportLanguage, value: unknown): string {
  const raw = rawText(language, value);
  if (language === 'en' || typeof value !== 'string') return raw;
  return Object.hasOwn(prose, value) ? prose[value] : `원문: ${raw}`;
}
export function patternLabel(language: ReportLanguage, code: string): string {
  return Object.hasOwn(patterns, code) ? patterns[code][language === 'ko' ? 1 : 0] : choose(language, 'Original: ', '원문: ') + rawText(language, code, 64);
}
export function warningLabel(language: ReportLanguage, code: string, legacy = false): string {
  const registry = legacy ? { ...warnings, ...legacyWarnings } : warnings;
  return Object.hasOwn(registry, code) ? `${registry[code][language === 'ko' ? 1 : 0]} (${rawText(language, code, 64)})` : choose(language, 'Unsupported coverage warning — report interpretation unavailable. Original: ', '지원하지 않는 분석 범위 경고 — 보고서를 해석할 수 없습니다. 원문: ') + rawText(language, code, 80);
}
export function factLabel(language: ReportLanguage, code: string): string {
  return language === 'en' ? rawText(language, code, 64) : Object.hasOwn(factLabels, code) ? factLabels[code] : `원문: ${rawText(language, code, 64)}`;
}
export function evidenceText(language: ReportLanguage, value: unknown, issue: { pattern: string; event_count: number; affected_flow_count: number }): string {
  // Exact v1 template, validated against typed facts: never replace substrings in raw evidence.
  if (language === 'ko' && Object.hasOwn(patterns, issue.pattern) && value === `${issue.event_count} ${issue.pattern} observations across ${issue.affected_flow_count} flows.`) {
    return `${issue.affected_flow_count}개 흐름에서 ${patternLabel(language, issue.pattern)} ${issue.event_count}건이 관찰되었습니다.`;
  }
  return translateProse(language, value);
}
