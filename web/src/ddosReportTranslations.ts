import type { ReportLanguage } from './reportLanguageContext';

export type Localized = readonly [en: string, ko: string];
export const choose = (language: ReportLanguage, value: Localized) => value[language === 'ko' ? 1 : 0];

export const attackTypes: Record<string, Localized> = {
  TCP_SYN_FLOOD: ['TCP SYN flood', 'TCP SYN 플러드'],
  TCP_ACK_FLOOD: ['TCP ACK flood', 'TCP ACK 플러드'],
  TCP_RST_FLOOD: ['TCP RST flood', 'TCP RST 플러드'],
  UDP_FLOOD: ['UDP flood', 'UDP 플러드'],
  ICMP_ECHO_FLOOD: ['ICMP echo flood', 'ICMP Echo 플러드'],
  ICMP_FLOOD: ['ICMP flood', 'ICMP 플러드'],
  POSSIBLE_REFLECTION_AMPLIFICATION: ['Possible reflection/amplification', '반사·증폭 공격 가능성'],
  MULTI_VECTOR: ['Multi-vector flood', '다중 벡터 플러드'],
};
export const objectives: Record<string, Localized> = {
  CONNECTION_STATE_EXHAUSTION: ['Possible connection-state resource exhaustion', '연결 상태 자원 고갈 가능성'],
  BANDWIDTH_EXHAUSTION: ['Possible bandwidth exhaustion', '대역폭 고갈 가능성'],
  PACKET_PROCESSING_EXHAUSTION: ['Possible packet-processing exhaustion', '패킷 처리 자원 고갈 가능성'],
  REFLECTED_BANDWIDTH_EXHAUSTION: ['Possible reflected bandwidth exhaustion', '반사 트래픽을 이용한 대역폭 고갈 가능성'],
  MULTI_RESOURCE_EXHAUSTION: ['Possible multi-resource exhaustion', '복수 자원 고갈 가능성'],
  UNKNOWN: ['Defensive objective unknown', '방어 관점 목적 불명'],
};
export const roles: Record<string, Localized> = {
  VICTIM_SIDE_INBOUND: ['Inbound traffic observed at the victim side', '피해 대상 측 인바운드 트래픽'],
  PARTICIPANT_SIDE_OUTBOUND: ['Outbound attack participation observed', '내부 호스트의 외부 공격 참여 트래픽'],
  UNKNOWN: ['Attack role unknown', '공격 역할 불명'],
};
export const recommendations: Record<string, Localized> = {
  PRESERVE_CAPTURE_AND_LOGS: ['Preserve capture and device/service logs', '캡처와 장비·서비스 로그 보존'],
  VERIFY_SERVICE_IMPACT: ['Verify measured service and infrastructure impact', '서비스 및 인프라 영향 실측 확인'],
  CONTACT_UPSTREAM_PROVIDER: ['Contact the upstream provider with measured facts', '측정 근거와 함께 상위 회선 사업자에 연락'],
  MONITOR_RECOVERY_AND_FALSE_POSITIVES: ['Monitor recovery and false positives', '복구 상태와 오탐 여부 모니터링'],
  ENABLE_SYN_PROXY_OR_COOKIES: ['Enable a SYN proxy or SYN cookies after review', '검토 후 SYN 프록시 또는 SYN 쿠키 활성화'],
  APPLY_EDGE_SYN_RATE_LIMIT: ['Apply a reviewed edge SYN rate limit', '검토된 경계 SYN 속도 제한 적용'],
  CHECK_SYN_BACKLOG_AND_CONNTRACK: ['Check SYN backlog and connection tracking pressure', 'SYN backlog와 연결 추적 부하 확인'],
  ENGAGE_SCRUBBING_OR_FLOWSPEC: ['Engage upstream scrubbing or reviewed FlowSpec', '상위 회선 스크러빙 또는 검토된 FlowSpec 적용'],
  FILTER_OR_RATE_LIMIT_UNUSED_UDP_SERVICES: ['Filter or rate-limit unused UDP services', '미사용 UDP 서비스 필터링 또는 속도 제한'],
  VALIDATE_REFLECTION_SOURCE_PORTS: ['Validate suspected reflection source ports', '의심 반사 서비스 source port 검증'],
  RATE_LIMIT_NONESSENTIAL_ICMP: ['Rate-limit nonessential ICMP after review', '검토 후 비필수 ICMP 속도 제한'],
  PRESERVE_PMTUD_AND_REQUIRED_ICMP: ['Preserve PMTUD and required ICMP', 'PMTUD와 필수 ICMP 유지'],
  APPLY_STATEFUL_TCP_VALIDATION: ['Apply stateful TCP validation at the edge', '경계에서 stateful TCP 검증 적용'],
  RATE_LIMIT_INVALID_TCP_FLAGS: ['Rate-limit invalid TCP flag patterns', '비정상 TCP flag 패턴 속도 제한'],
  CHECK_MIDDLEBOX_RESET_SOURCES: ['Check middlebox and service reset sources', '중간 장비 및 서비스의 reset 발생 원인 확인'],
  ISOLATE_INTERNAL_SOURCES: ['Isolate confirmed internal participating sources', '확인된 내부 공격 참여 source 격리'],
  APPLY_EGRESS_RATE_LIMIT: ['Apply reviewed egress rate limits', '검토된 egress 속도 제한 적용'],
  ENFORCE_EGRESS_ANTISPOOFING: ['Enforce egress anti-spoofing controls', 'egress anti-spoofing 통제 적용'],
};
export const recommendationScopes: Record<string, Localized> = {
  LOCAL: ['Local scope', '로컬 적용 범위'],
  UPSTREAM: ['Upstream/provider scope', '상위 회선·사업자 적용 범위'],
};
export const recommendationCaveats: Record<string, Localized> = {
  PRESERVE_CAPTURE_AND_LOGS: ['Apply retention and access controls to preserved evidence.', '보존 증거에 보존 기간과 접근 통제를 적용하세요.'],
  VERIFY_SERVICE_IMPACT: ['Confirm impact with service and infrastructure telemetry.', '서비스 및 인프라 telemetry로 영향을 확인하세요.'],
  CONTACT_UPSTREAM_PROVIDER: ['Share only reviewed measured facts; source attribution is unconfirmed.', '검토된 측정 사실만 공유하며 source 귀속은 미확인입니다.'],
  MONITOR_RECOVERY_AND_FALSE_POSITIVES: ['Rollback controls if legitimate traffic is materially affected.', '정상 트래픽 영향이 크면 통제를 rollback하세요.'],
  ENABLE_SYN_PROXY_OR_COOKIES: ['Validate platform support and connection behavior before rollout.', '적용 전 플랫폼 지원과 연결 동작을 검증하세요.'],
  APPLY_EDGE_SYN_RATE_LIMIT: ['Rate limits can drop legitimate bursts; stage and keep rollback ready.', '속도 제한은 정상 burst를 차단할 수 있으므로 단계 적용하고 rollback을 준비하세요.'],
  CHECK_SYN_BACKLOG_AND_CONNTRACK: ['Observation alone does not prove resource exhaustion.', '관찰만으로 자원 고갈이 입증되지는 않습니다.'],
  ENGAGE_SCRUBBING_OR_FLOWSPEC: ['Confirm provider scope, match criteria, cost, and rollback before activation.', '활성화 전 사업자 범위·match 조건·비용·rollback을 확인하세요.'],
  FILTER_OR_RATE_LIMIT_UNUSED_UDP_SERVICES: ['Verify service dependencies before filtering or limiting traffic.', '필터링·제한 전 서비스 의존성을 확인하세요.'],
  VALIDATE_REFLECTION_SOURCE_PORTS: ['A source port alone does not prove reflection or spoofing.', 'source port만으로 reflection 또는 spoofing이 입증되지는 않습니다.'],
  RATE_LIMIT_NONESSENTIAL_ICMP: ['Do not block all ICMP; preserve required control traffic.', 'ICMP 전체를 차단하지 말고 필수 제어 트래픽을 유지하세요.'],
  PRESERVE_PMTUD_AND_REQUIRED_ICMP: ['Validate PMTUD and operational ICMP requirements.', 'PMTUD 및 운영상 필요한 ICMP를 검증하세요.'],
  APPLY_STATEFUL_TCP_VALIDATION: ['Check state-table capacity and asymmetric routing before activation.', '활성화 전 state table 용량과 비대칭 routing을 확인하세요.'],
  RATE_LIMIT_INVALID_TCP_FLAGS: ['Validate the match against legitimate middleboxes and clients.', '정상 middlebox와 client 트래픽에 대한 match를 검증하세요.'],
  CHECK_MIDDLEBOX_RESET_SOURCES: ['RST traffic may be a normal defensive or service response.', 'RST 트래픽은 정상 방어 장비 또는 서비스 응답일 수 있습니다.'],
  ISOLATE_INTERNAL_SOURCES: ['Confirm host ownership and participation before isolation.', '격리 전 host 소유권과 공격 참여를 확인하세요.'],
  APPLY_EGRESS_RATE_LIMIT: ['Stage limits and monitor legitimate outbound service impact.', '제한을 단계 적용하고 정상 outbound 서비스 영향을 관찰하세요.'],
  ENFORCE_EGRESS_ANTISPOOFING: ['Test legitimate routing and failover paths before enforcement.', '적용 전 정상 routing 및 failover 경로를 시험하세요.'],
};
export const warnings: Record<string, Localized> = {
  INPUT_RECORD_LIMIT_REACHED: ['The input record limit was reached.', '입력 레코드 한도에 도달했습니다.'],
  BASELINE_UNAVAILABLE: ['No qualified baseline; classification is limited to possible.', '적격 기준선이 없어 가능성 수준으로 제한됩니다.'],
  SAMPLE_WINDOW_SHORT: ['The observation window is short.', '관찰 구간이 짧습니다.'],
  DUPLICATE_CAPTURE_NOT_EXCLUDED: ['Multiple sensors were combined; duplicate capture was not excluded.', '여러 센서 관측을 합산했으며 중복 캡처를 배제하지 못했습니다.'],
  PARSER_SKIPPED_PACKETS: ['The parser skipped one or more captured packets.', '파서가 캡처된 일부 패킷을 제외했습니다.'],
  SENSOR_DROPS_REPORTED: ['A selected sensor reported packet drops.', '선택한 센서에서 패킷 drop이 보고되었습니다.'],
  SENSOR_CLOCK_SKEW: ['A selected sensor reported material clock skew.', '선택한 센서에서 유의미한 시계 오차가 보고되었습니다.'],
  SENSOR_CAPTURE_QUALITY_UNAVAILABLE: ['Job-scoped sensor drop and clock-quality telemetry was unavailable.', '작업 범위의 센서 drop 및 시계 품질 telemetry를 확인할 수 없습니다.'],
  PARTIAL_CAPTURE: ['The capture or dataset is partial.', '캡처 또는 데이터셋이 부분적입니다.'],
  DOS_LIKE_TRAFFIC: ['High-volume single-source DoS-like traffic was not classified as DDoS.', '단일 source의 고용량 DoS 유사 트래픽은 DDoS로 분류하지 않았습니다.'],
  AMBIGUOUS_DIRECTION: ['Some records had ambiguous direction and were skipped.', '방향이 불명확한 일부 레코드를 제외했습니다.'],
  INCOMPLETE_RECORDS: ['Some invalid or incomplete records were skipped.', '유효하지 않거나 불완전한 일부 레코드를 제외했습니다.'],
  TARGET_LIMIT_REACHED: ['The target tracking limit was reached.', '대상 추적 한도에 도달했습니다.'],
  BUCKET_LIMIT_REACHED: ['The time-bucket tracking limit was reached.', '시간 bucket 추적 한도에 도달했습니다.'],
  FINDING_LIMIT_REACHED: ['The finding publication limit was reached.', '발견 항목 게시 한도에 도달했습니다.'],
};
export const uncertainties: Record<string, Localized> = {
  BASELINE_UNAVAILABLE: warnings.BASELINE_UNAVAILABLE,
  TCP_RESPONSE_VISIBILITY_UNKNOWN: ['TCP response visibility is incomplete.', 'TCP 응답 관측 범위가 불완전합니다.'],
  TCP_PAYLOAD_VISIBILITY_UNKNOWN: ['TCP payload visibility is incomplete.', 'TCP payload 관측 범위가 불완전합니다.'],
  SUBSTANTIAL_TCP_RESPONSES_OBSERVED: ['Substantial TCP responses weaken the SYN-flood hypothesis.', '상당한 TCP 응답이 관측되어 SYN 플러드 가설이 약해집니다.'],
  ACK_TRAFFIC_MAY_BE_LEGITIMATE: ['ACK traffic may include legitimate responses.', 'ACK 트래픽에는 정상 응답이 포함될 수 있습니다.'],
  RESETS_MAY_BE_DEFENSIVE_RESPONSES: ['RST traffic may be a defensive or service response.', 'RST 트래픽은 방어 장비 또는 서비스 응답일 수 있습니다.'],
  AMPLIFICATION_RATIO_UNOBSERVED: ['No request/response amplification ratio was measured.', '요청·응답 증폭비를 측정하지 못했습니다.'],
  SOURCE_SPOOFING_UNCONFIRMED: ['Source spoofing is not confirmed.', 'source spoofing은 확인되지 않았습니다.'],
  ICMP_TYPE_UNAVAILABLE: ['ICMP type metadata is unavailable.', 'ICMP type metadata가 없습니다.'],
  SHARED_TARGET_DOES_NOT_PROVE_SHARED_ACTOR: ['A shared target does not prove a shared actor.', '공통 대상이 동일 공격 주체를 입증하지 않습니다.'],
  BUCKET_LIMIT_REACHED: warnings.BUCKET_LIMIT_REACHED,
};
export const limitations: Record<string, Localized> = {
  NO_FINDING_DOES_NOT_PROVE_HEALTH: ['No finding does not prove the network or service is healthy.', '발견 항목이 없더라도 네트워크나 서비스가 정상임을 입증하지 않습니다.'],
  OBSERVED_SOURCES_ARE_NOT_CONFIRMED_ATTACKERS: ['Observed sources are not confirmed attacker identities.', '관찰 source는 확인된 공격자 신원이 아닙니다.'],
  TRAFFIC_SHAPE_DOES_NOT_PROVE_SERVICE_IMPACT: ['Traffic shape does not prove service impact.', '트래픽 형태만으로 서비스 영향을 입증할 수 없습니다.'],
  APPLICATION_LAYER_FLOODS_NOT_CLASSIFIED: ['Application-layer floods are not classified.', '애플리케이션 계층 플러드는 분류하지 않습니다.'],
};
export const metricLabels: Record<string, Localized> = {
  packet_count: ['Packets', '패킷'], byte_count: ['Bytes', '바이트'], duration_seconds: ['Duration (seconds)', '지속 시간(초)'],
  average_packets_per_second: ['Average packets/second', '평균 PPS'], average_bits_per_second: ['Average bits/second', '평균 bps'],
  peak_packets_per_second: ['Observed peak packets/second', '관찰 최대 PPS'], peak_bits_per_second: ['Observed peak bits/second', '관찰 최대 bps'],
  peak_is_lower_bound: ['Peak is a lower bound', '최대값이 하한값인지 여부'], direction_source: ['Direction source', '방향 판정 근거'],
  record_count: ['Flow records', 'Flow 레코드'], distinct_sources: ['Observed distinct sources', '관찰 source 수'], distinct_sensors: ['Sensors', '센서 수'], syn_only_ratio: ['SYN-only ratio', 'SYN-only 비율'],
  ack_only_ratio: ['ACK-only ratio', 'ACK-only 비율'], rst_ratio: ['RST ratio', 'RST 비율'], fin_ratio: ['FIN ratio', 'FIN 비율'], payload_packet_ratio: ['Payload packet ratio', 'payload 패킷 비율'], response_ratio: ['Observed response ratio', '관찰 응답 비율'],
  baseline_packets_per_second: ['Baseline packets/second', '기준선 PPS'], baseline_ratio: ['Baseline ratio', '기준선 대비 비율'], robust_z_score: ['Robust z-score', 'Robust z-score'],
  measurement_precision: ['Measurement precision', '측정 정밀도'], average_packet_bytes: ['Average packet bytes', '평균 패킷 크기'],
  dominant_reflection_source_port: ['Dominant reflection source port', '주요 반사 source port'], reflection_source_port_ratio: ['Reflection source-port ratio', '반사 source port 비율'],
  amplification_ratio: ['Measured amplification ratio', '측정 증폭비'], icmp_type_observed_packets: ['Packets with ICMP type', 'ICMP type 관찰 패킷'],
  icmp_echo_request_ratio: ['ICMP echo-request ratio', 'ICMP echo request 비율'], component_types: ['Component attack types', '구성 공격 유형'], component_finding_count: ['Component findings', '구성 발견 항목 수'],
};
