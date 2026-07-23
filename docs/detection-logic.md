# C2Hunter 탐지 로직

## 1. 분석 계약

초기 MVP는 규칙·통계 기반이며 detector는 독립 모듈이다.

```python
class Detector:
    name: str
    version: str
    def analyze(self, context: AnalysisContext) -> list[Evidence]: ...
```

`AnalysisContext`는 dataset/time range, selected sensors, internal CIDRs, normalized Flow/event query, clock offsets, profile parameters, allowlist snapshot을 제공한다. `Evidence`는 candidate IP, type, detector/version, raw metric, 0 이상 contribution, 설명, 관련 host/sensor/time, 신뢰도·warning을 포함한다. detector는 최종 점수를 직접 덮어쓰지 않는다.

## 2. 전처리

1. **범위 제한**: job/dataset/time/sensor/protocol 조건으로 streaming query한다.
2. **IP 역할 분류**: configurable internal CIDR에 포함된 endpoint를 내부로 본다. 사설·공인 대역 모두 허용한다. 양쪽/어느 쪽도 불명확하면 confidence를 낮추고 임의 추정하지 않는다.
3. **방향 정규화**: sensor direction을 우선하며 `UNKNOWN`은 그대로 유지한다. 명령-공격 detector는 확정 방향만 강한 근거로 사용한다.
4. **시계 보정**: heartbeat offset을 관찰 timestamp에 적용하고 기본 ±2초 tolerance를 사용한다. offset >2초 센서는 `DEGRADED`, 증거와 결과에 경고/신뢰도 저하를 표시한다.
5. **중복 제거**: 5-tuple, IP ID, TCP seq, payload length/hash, timestamp bucket으로 canonical packet을 정한다. sensor observation은 별도 집합으로 보존한다.
6. **후보 universe**: 내부↔외부 Flow의 외부 IP를 후보로 만든다. internal/allowlist 명시 제외 대상은 suppression 통계만 남긴다.
7. **time bucket/feature**: 외부 IP·내부 host·sensor·protocol/port별 count/bytes/size/fingerprint 시계열을 bounded bucket으로 집계한다.

## 3. Detector

### 3.1 COMMON_DESTINATION (최대 20)

외부 IP별로 고유 내부 IP 수, 연결 수, 센서 수, 지속 시간, host당 평균 연결 수, 공통 port 비율, 공통 payload fingerprint 비율을 계산한다.

- `minimum_distinct_clients` 미만은 점수를 주지 않거나 표본 부족 감점을 유발한다.
- host 수는 포화형 정규화(`min(1, distinct/min_target)`)하고 반복·port/fingerprint 공통성과 지속 시간을 보조 계수로 사용한다.
- 단일 host만 관찰되면 최대 -20 감점 대상이다.
- DNS/NTP/CDN/cloud/업무 서버는 후처리 감점 또는 제외한다.

Evidence metrics: distinct hosts, connections, sensors, duration, connections/host, dominant port ratio, fingerprint ratio.

### 3.2 PERIODIC_BEACON (최대 15)

내부 host↔외부 IP event timestamp를 정렬하고 inter-arrival time을 streaming window로 계산한다. 최소 표본 기본값은 요청의 `periodicity_min_samples`(예: 5)다.

계산값:
- mean/std inter-arrival, coefficient of variation(CV)
- 반복 횟수, duration, lag autocorrelation
- packet-size CV/반복성
- host별 dominant period와 sensor 집합

평균 간격 대비 jitter가 ±10~30%인 패턴을 허용한다. 단일 host regularity, 여러 host의 period 일치율, 장기 지속성, size 유사성, multi-sensor 재현성을 결합한다. 완전 고정 간격만 탐지하도록 equality 비교하지 않는다.

Evidence metrics: sample count, period, jitter/CV, autocorrelation, size similarity, matching hosts/sensors.

### 3.2.1 SINGLE_HOST_BEACON (최대 35)

기존 다중-host 중심 탐지의 사각지대를 보완한다. 한 내부 host만 관찰되더라도 최소 5개
표본, interval CV ≤0.30, 평균 packet count ≤10을 만족하고 동일 Payload hash 비율이
60% 이상이거나 packet-size CV가 0.20 이하이면 복합 beacon evidence를 만든다.
이 evidence가 있는 단일 host 감점은 -10으로 완화한다. 따라서 낮은 점수까지 표시하는
hunting 설정에서는 단일 감염 초기 단계도 검토할 수 있다.

Evidence metrics: sample count, period/CV, payload stability, size CV, average packets, sensors.

### 3.2.2 ANALYST_PAYLOAD_SIGNATURE (최대 80)

분석가가 `C2`로 라벨링한 Flow에서 승인한 Payload signature를 새 분석 시점에 snapshot해
적용한다. protocol, direction, 외부 service port를 공통 guard로 사용한다.

- 전체 Payload SHA-256이 같으면 `EXACT`: contribution 80, confidence 1.0, action `alert`.
  분석가가 확인한 동일 payload의 재관찰이므로 단일-host/표본 부족 감점을 적용하지 않는다.
- exact가 아니어도 prefix hash 또는 64-bit SimHash, 길이, entropy 조건을 모두 만족하면
  `STRUCTURAL`: contribution 60, confidence 0.7, action `monitor`. 단일-host 감점은 유지한다.

원문 Payload는 signature에 저장하지 않는다. Evidence에는 signature ID/version, match mode,
길이·entropy 차이, SimHash Hamming distance와 적용 threshold를 보존한다. 완료된 분석에는
새 signature를 소급 적용하지 않고 reanalysis를 생성한다. 상세 계약과 안전 경계는
[분석가 주도 탐지 명세](human-guided-detection.md)를 따른다.

### 3.3 SYNCHRONIZED_COMMUNICATION (최대 15)

외부 IP별 접속을 configurable window(기본 2초)로 묶는다. 한 window의 distinct host 수와 sensor 수를 세고 같은 패턴이 반복되는 횟수를 계산한다. 한 번의 우연한 burst보다 반복 cluster에 높은 점수를 준다. clock tolerance를 window에 반영하되 skew warning이 있으면 confidence를 낮춘다.

Evidence metrics: window seconds, synchronized hosts, event count, repetition count, sensors, observed spread.

### 3.4 COMMAND_ATTACK_CORRELATION (최대 25)

가장 강한 근거이며 확정된 방향성을 요구한다.

1. 외부 후보→다수 내부 host의 작고 동기화된 `INBOUND` event를 command seed로 찾는다.
2. seed 후 configurable 1~30초 창(요청 예 기본 10초)에서 같은 host의 `OUTBOUND` packet/PPS/bytes 증가를 계산한다.
3. seed 이전 동등 길이의 baseline과 비교해 increase ratio를 산출한다(0 baseline은 최소 절대 packet/PPS 조건과 epsilon으로 처리).
4. host 간 공통 attack target IP/port/protocol, packet size와 시작 시점 일치를 확인한다.
5. 여러 센서에서 같은 시작을 관찰하면 confidence/contribution을 높인다.

`UNKNOWN` 방향, 작은 표본, baseline 부재는 명시적 warning이며 높은 점수를 단독 부여하지 않는다. 관련 attack target을 별도 결과로 저장한다.

Evidence metrics: command size/count, affected hosts, lag distribution, baseline/peak PPS, increase ratio, target/port/protocol, packet-size similarity, sensors.

### 3.5 LOW_VOLUME_PERSISTENCE_RARITY (최대 5)

긴 duration, bucket당 1~소수 packet, 작은 bytes, 외부 IP 안정성, 전체 데이터셋 대비 목적지 희귀성을 결합한다. 희귀성은 `contacting_hosts/total_internal_hosts`와 destination frequency baseline을 함께 사용하여 작은 데이터셋의 왜곡을 경고한다.

### 3.6 PROTOCOL_PAYLOAD_SIMILARITY (최대 10)

여러 host에 걸쳐 destination port, TLS/client/server hello 및 certificate fingerprint, HTTP Host/URI 구조, DNS query pattern/TXT size, first payload hash, packet-size sequence, request/response ratio의 dominant cluster 비율을 계산한다. 원문 Payload 대신 hash/statistics를 사용한다. CDN처럼 IP는 같지만 Host/SNI가 다양한 경우 similarity가 낮아져 공통 목적지 단독 오탐을 억제한다.

### 3.7 MULTI_SENSOR_CONTEXT (최대 10)

`destination_ip, destination_port, protocol, payload/tls fingerprint, dns_domain, time_bucket` 키를 조합해 독립 센서 관찰을 확인한다. 중복 제거된 logical packet count와 별개로 observation 집합을 사용한다. 동일 미러 패킷 하나가 두 센서에 보인 것만으로 강한 점수를 주지 않고, 각 센서의 distinct host/event pattern 재현을 요구한다. 기본 timestamp tolerance는 ±2초다.

## 4. 점수 모델

기본 양의 contribution 상한:

| Evidence | 최대 |
|---|---:|
| COMMON_DESTINATION | 20 |
| PERIODIC_BEACON | 15 |
| SINGLE_HOST_BEACON | 35 |
| ANALYST_PAYLOAD_SIGNATURE | 80 |
| SYNCHRONIZED_COMMUNICATION | 15 |
| COMMAND_ATTACK_CORRELATION | 25 |
| MULTI_SENSOR_CONTEXT | 10 |
| PROTOCOL_PAYLOAD_SIMILARITY | 10 |
| LOW_VOLUME_PERSISTENCE_RARITY | 5 |

감점/제외:

| 조건 | 처리 |
|---|---:|
| 명시적 allowlist IP/CIDR/domain/fingerprint match | 후보 제외, suppression 통계 기록 |
| DNS/NTP 공용 인프라 | 최대 -30 |
| CDN/대형 cloud 공유 IP | 최대 -20 |
| 내부 업무 서버 | 최대 -40 |
| 단일 내부 host | 최대 -20 (`SINGLE_HOST_BEACON`은 -10, analyst exact는 미적용) |
| 표본 부족 | 최대 -20 |

`score = clamp(0, 100, sum(capped contributions) + sum(negative adjustments))`로 계산한다. 동일 detector가 여러 evidence를 내더라도 detector별 최대치를 넘지 않는다. profile에서 threshold/weight를 바꿀 수 있지만 run에 snapshot한다.

Severity는 `0–39 LOW`, `40–59 MEDIUM`, `60–79 HIGH`, `80–100 CRITICAL`이다. 후보 최소 점수는 반환 필터이지 원 evidence 삭제 기준이 아니다.

## 5. 오탐 제어와 설명 가능성

- allowlist는 IP, CIDR, domain suffix, TLS/certificate fingerprint 및 만료를 지원한다.
- 공용 DNS/NTP 분류는 protocol/port만으로 확정하지 않고 operator policy와 metadata를 함께 사용한다.
- CDN은 Host/SNI 다양성과 cloud policy를 활용한다.
- 모든 감점 및 제외 match도 rule version, 지표, 이유를 저장한다.
- 결과는 관련 host, sensor, 시간, detector/version, 입력 지표, contribution, confidence/warning, 관련 PCAP과 attack target을 제공한다.
- 데이터 손실, 일부 센서 실패, clock skew, PCAP 만료를 결과 warning에 포함한다.

## 6. 합성 시나리오의 판정 oracle

| 시나리오 | 필수 판정 |
|---|---|
| A: 50 hosts, 30초±3초 beacon | score ≥60, `PERIODIC_BEACON`, host=50 |
| B: 100 hosts, command 후 1~3초 UDP burst, 2 sensors | score ≥80, `COMMAND_ATTACK_CORRELATION`, `MULTI_SENSOR_CONTEXT`, target 식별 |
| C: benign DNS/NTP | HIGH/CRITICAL 아님, 공용 서비스 감점 evidence |
| D: CDN, 다양한 Host/SNI | 공통 목적지만으로 HIGH 아님 |
| E: sensor duplicate | logical packet count dedup, sensor observations=2 |
| F: 3초 clock skew | sensor DEGRADED, 결과 warning/confidence 저하 |
| G: Sensor B 중단 | `PARTIALLY_COMPLETED`, Sensor A 분석, 손실/실패 표시 |

고정 seed를 사용하고 외부 인터넷이나 실제 C2에 연결하지 않는다.

## 7. 단위·성능 검증

각 detector는 경계값, 정상 음성, 작은 표본, jitter/skew, 중복, IPv4/IPv6를 독립 테스트한다. 필수 단위 대상은 방향, internal IP, flow key/timeout, dedup, beacon, synchronization, command correlation, score, allowlist, time correction, retention, export filter와 API validation이다. Detector coverage는 90% 이상이다.

100만 패킷은 chunk/streaming으로 ingestion→flow→모든 detector→저장까지 수행한다. peak RSS와 단계별 시간을 측정하고 `artifacts/benchmark-1m.json`, `.md`에 기록한다. OOM/데이터 손실 없음은 필수이고 기준 시스템 180초/Controller RSS 8GB 미만은 목표 및 병목 보고 대상이다.
