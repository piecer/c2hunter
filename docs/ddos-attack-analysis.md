# DDoS 공격 트래픽 분석

## 목적

`ddos_attack`은 C2Hunter의 독립 분석 도메인이다. 관찰된 TCP/UDP/ICMP 트래픽에서 DDoS 형태를 분류하고, 보호 대상 또는 내부 참여 호스트 관점의 역할, 방어 대상 자원에 대한 목적 가설, 운영자 승인이 필요한 대응 항목을 생성한다.

이 결과는 공격자 귀속, 서비스 장애 입증, source spoofing 확인 또는 자동 차단 명령이 아니다. 기존 C2 Candidate/TI/MISP/AI 자동화로 전달되지 않는다.

## 지원 유형

- `TCP_SYN_FLOOD`: SYN-only 비율이 지배적인 분산 TCP 트래픽
- `TCP_ACK_FLOOD`: ACK-only 비율이 지배적인 분산 TCP 트래픽
- `TCP_RST_FLOOD`: RST 비율이 지배적인 분산 TCP 트래픽
- `UDP_FLOOD`: 반사 형태로 한정되지 않는 분산 UDP 트래픽
- `ICMP_ECHO_FLOOD`: packet-level ICMP type이 있는 echo request 중심 트래픽
- `ICMP_FLOOD`: type metadata가 없거나 echo 중심이 아닌 ICMP 트래픽
- `POSSIBLE_REFLECTION_AMPLIFICATION`: 알려진 reflection service source port와 큰 응답 크기가 관찰된 victim-side UDP 형태
- `MULTI_VECTOR`: 같은 target에 겹쳐 관찰된 복수 flood 유형

HTTP request flood와 TLS handshake flood는 현재 Flow 계약에 필요한 L7 요청 의미가 없어 분류하지 않는다.

## 판정과 목적

Report verdict는 `attack_likely`, `suspicious_traffic`, `no_clear_attack`, `insufficient_evidence` 중 하나다. 개별 positive finding의 likelihood는 `LIKELY` 또는 `POSSIBLE`이다. 지원되는 형태가 없을 때 coverage가 완전하면 `no_clear_attack`, 불완전하면 `insufficient_evidence`를 사용하며 finding에 `NOT_OBSERVED` 또는 `INSUFFICIENT_EVIDENCE`를 넣지 않는다. 절대 traffic floor, 관찰 source 분산, protocol/flag 형태, 적격 baseline을 함께 사용한다. baseline 또는 TCP reverse-response 가시성이 없으면 SYN positive finding은 최대 `POSSIBLE`이다. source 수가 부족한 고용량 traffic은 `DOS_LIKE_TRAFFIC` warning을 내고 DDoS로 확정하지 않는다.

목적은 공격자의 동기가 아니라 방어 관점의 자원 고갈 가설이다.

- SYN flood: connection-state exhaustion
- ACK/RST 또는 작은 packet 중심 flood: packet-processing exhaustion
- UDP/ICMP: bandwidth 또는 packet-processing exhaustion
- reflection 형태: reflected bandwidth exhaustion
- multi-vector: multi-resource exhaustion

## 측정 정밀도

- `PACKET`: `packet_evidence_complete=true`, `packet_count=1`. 1초 bucket peak를 계산할 수 있다.
- `AGGREGATED_FLOW`: sensor 집계 Flow. target의 최초 시작부터 최종 flow 종료까지의 구간에 대해 합산 packet/byte 평균률을 계산하며 가상의 packet timestamp나 peak를 만들지 않는다.
- `MIXED`: packet과 aggregate가 함께 있을 때 packet subset peak는 하한으로 표시한다.

Sensor 집계 TCP Flow는 `transport_payload_packet_count`로 payload가 있었던 packet 수를
명시한다. 이 값이 없는 이전 Sensor record에서도 ACK-dominant 형태는 숨기지 않지만
`TCP_PAYLOAD_VISIBILITY_UNKNOWN`으로 payload 관측 한계를 표시하고 likelihood를
`POSSIBLE`로 제한한다.

동일 packet의 multi-sensor mirror dedup을 입증할 fingerprint가 없으면 source/sensor 합산이 중복될 수 있으므로 `DUPLICATE_CAPTURE_NOT_EXCLUDED` warning을 표시한다.

Controller는 분석기 실행 전에 수집 범위 정보를 함께 snapshot한다. 업로드 PCAP에서 parser가
packet을 제외했으면 `PARSER_SKIPPED_PACKETS`, capture limit 또는 중단으로 데이터셋이
부분적이면 `PARTIAL_CAPTURE`를 표시한다. Sensor 작업에 job-scoped drop/clock telemetry가
없으면 현재 heartbeat의 누적 수치를 해당 작업에 잘못 귀속하지 않고
`SENSOR_CAPTURE_QUALITY_UNAVAILABLE`로 표시한다. 이들 coverage qualifier가 있으면
`no_clear_attack`과 high-confidence 판정을 금지한다.

## 기본 threshold

| Parameter | Default |
|---|---:|
| `ddos_bucket_seconds` | 1 |
| `ddos_min_duration_seconds` | 3 |
| `ddos_min_source_count` | 20 |
| `ddos_min_packet_count` | 1,000 |
| `ddos_min_packets_per_second` | 100 |
| `ddos_min_bits_per_second` | 1,000,000 |
| `ddos_baseline_min_buckets` | 20 |
| `ddos_baseline_ratio` | 5.0 |
| `ddos_mad_z_threshold` | 6.0 |
| `ddos_protocol_share_threshold` | 0.80 |
| `ddos_tcp_flag_share_threshold` | 0.80 |
| `ddos_response_ratio_max` | 0.20 |
| `ddos_reflection_port_share_threshold` | 0.60 |
| `ddos_reflection_min_average_packet_bytes` | 256 |
| `ddos_overlap_window_seconds` | 10 |

Reflection source-port catalog v1은 17, 19, 53, 123, 389, 1900, 11211이다. source port만으로 amplification을 확정하지 않으며 request/response 증폭비를 관찰하지 못하면 `amplification_ratio=null`을 유지한다.

## 안전한 대응 출력

대응은 닫힌 code catalog와 `requires_human_approval=true`로 제공한다. 유형별 조치가 먼저 오고, 증거 보존·영향 실측·upstream 연락·복구 및 오탐 모니터링이 뒤따른다. UI는 ko/en local registry로 번역하며 unknown code는 raw text를 반사하지 않고 보고서 전체를 fail closed한다.

RTBH/FlowSpec/scrubbing은 upstream 승인과 영향 검토가 필요하다. ICMP 전체 차단은 PMTUD를 손상할 수 있어 권고하지 않는다. 이 모듈은 방화벽, router, WAF 또는 cloud API를 호출하지 않는다.

## Bounds와 coverage

- 전체 입력 record: 2,000,000
- 유효 target record가 100개 미만이면 `SAMPLE_WINDOW_SHORT`로 표시하고 finding confidence를 낮춘다. 관측된 positive finding은 보존한다.
- target state: 4,096
- target당 packet bucket: 3,600
- published finding: 100
- finding당 evidence/uncertainty/recommendation code: 8

limit+1에서 warning, `counts_are_lower_bounds=true`, `coverage_complete=false`를 기록하고 `no_clear_attack`을 금지한다. 작업 목록은 compact `ddos_attack_summary`만 반환한다. full `ddos_attack` report는 작업 상세 및 inline/PCAP 생성 응답에서 제공한다.

## 실행 예

PCAP upload:

```text
POST /api/v1/pcap-analysis-jobs?name=case&filename=capture.pcap&analysis_module=ddos_attack
Content-Type: application/vnd.tcpdump.pcap
```

Live/Historical job은 기존 `/api/v1/analysis-jobs` envelope에서 `analysis.module`을 `ddos_attack`으로 설정한다. 재분석은 원 dataset과 snapshot을 재사용하며 DDoS threshold만 선택적으로 override할 수 있다. C2 detector weight는 DDoS 재분석에서 거부한다.

## 검증

```text
.venv/bin/pytest -q analysis/tests/test_ddos_attack.py controller/tests/test_ddos_attack_api.py
npm --prefix web run test:unit -- DDoSAttack.test.tsx
make test
make lint
make build
make test-coverage
make benchmark-ddos-analysis
```

Benchmark는 양의 bounded record 수, 3회 실행 시간, source revision, runtime/host 정보, 실제 analyzer 상수와 effective threshold를 JSON/Markdown artifact에 기록한다.

완료 판정에는 실제 Controller, compatible worker, Web UI와 bounded LIVE sensor 경로가 필요하다. fixture 또는 inline POC만으로 production path를 입증하지 않는다.
