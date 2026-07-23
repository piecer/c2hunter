# 분석가 주도 C2 Flow/Payload 탐지 명세

## 1. 목적

C2Hunter의 기존 통계·행위 탐지에서 놓친 통신을 분석가가 직접 보완할 수 있게 한다.
분석가는 분석 결과의 특정 Flow를 `C2` 또는 `BENIGN`으로 라벨링하고, `C2` Flow의
Payload 및 통신 문맥에서 설명 가능한 특징 프로파일을 만든다. 이후 분석은 활성
프로파일과 일치하는 Flow의 외부 상대 IP를 C2 후보로 추출하고 일치 근거를 제공한다.

이 기능은 지도학습 모델이 아니라 **분석가가 승인한 결정론적 탐지 프로파일**이다.
단일 샘플을 일반화하는 위험을 제한하기 위해 정확 일치와 유사 일치를 구분하며,
자동 차단 기능은 제공하지 않는다.

## 2. 근거 체인

```text
원본 PCAP/센서 Flow
  → 정규화된 Flow와 비가역 Payload 특징
  → 분석가 C2/BENIGN 라벨
  → 버전이 고정된 Payload signature
  → 향후 Flow의 exact/structural match
  → 외부 상대 IP Candidate와 설명 가능한 Evidence
```

다음 값은 서로 구분해 보존한다.

- 원 관찰: job, sensor, timestamp, 5-tuple, direction, packet/byte count
- 정규화 특징: Payload hash, prefix hash, 길이, entropy, printable ratio, SimHash
- 분석가 판단: verdict, confidence, note, actor, occurred_at
- 파생 signature: source label/flow, match 조건, 버전, 상태
- 탐지 결과: matched signature, match mode, 비교값, confidence, first/last seen

## 3. 범위

### 3.1 포함

1. Job의 전체 Flow를 페이지 단위로 조회하며, detector가 Candidate로 승격하지 않은 Flow도
   분석가가 직접 검색·검토할 수 있다.
2. PCAP 원본이 보존된 경우 선택한 Flow의 Payload를 최대 256 bytes까지 명시적으로
   미리본다. 미리보기는 signature나 job metadata에 저장하지 않는다.
3. Flow를 `C2` 또는 `BENIGN`으로 라벨링한다.
4. `C2` 라벨에서 Payload signature를 생성한다.
5. signature를 조회, 이름/설명 수정, 활성화/비활성화한다.
6. 활성 signature snapshot을 새 분석 또는 재분석에 포함한다.
7. signature 일치 Flow의 외부 상대 IP를 Candidate로 생성한다.
8. exact와 structural match를 서로 다른 confidence와 점수로 표시한다.
9. 라벨과 signature 변경을 감사 가능한 객체 이력으로 남긴다.

### 3.2 제외

- Payload 원문 상시 저장
- 한 개 라벨을 이용한 확률 모델 또는 온라인 ML 학습
- C2 접속, 명령 재생, 능동 스캔
- signature 일치만으로 방화벽/IPS 자동 차단
- 기존 완료 Job 결과의 제자리 수정

완료된 Job은 불변이다. 새 signature를 기존 데이터에 적용하려면 reanalysis를 생성한다.

## 4. Payload 특징

특징은 첫 번째 non-empty L4 Payload에서 계산한다. 집계 Flow도 동일한 기준을 사용한다.

| 필드 | 정의 | 용도 |
|---|---|---|
| `payload_hash` | 전체 Payload SHA-256 | exact match |
| `payload_prefix_hash` | 첫 32 bytes의 SHA-256 | 고정 header/prefix |
| `payload_length` | Payload byte 길이 | 구조 검증 |
| `payload_entropy` | Shannon entropy, 0~8, 소수점 4자리 | 인코딩/암호화 형태 |
| `payload_printable_ratio` | ASCII printable 및 CR/LF/TAB 비율 | text/binary 구분 |
| `payload_simhash` | 3-byte shingle의 64-bit SimHash, 16자리 hex | 소규모 byte 변형 허용 |

SimHash의 shingle hash는 FNV-1a 64-bit를 사용한다. 각 bit별 vote가 0 이상이면 결과 bit를
1로 한다. 3 bytes 미만 Payload는 전체 Payload를 한 shingle로 사용한다. Python PCAP
parser와 Go Sensor가 동일한 test vector를 통과해야 한다.

원문 Payload가 없는 기존 Flow는 보유한 `payload_hash`로 exact signature를 만들 수
있다. structural signature는 필요한 특징이 수집된 이후 Flow에서만 활성화한다.

## 5. Flow 식별

`flow_id`는 다음 canonical JSON의 SHA-256 앞 24자리다.

```text
job_id, sensor_id, timestamp, source_ip, destination_ip,
source_port, destination_port, protocol, direction,
payload_hash, packet_count, total_bytes
```

키 순서와 구분자는 구현에서 고정한다. `flow_id`는 Job 내부 식별자이며 다른 Job의
Flow와 혼용하지 않는다.

## 6. 라벨 모델

```json
{
  "id": "uuid",
  "job_id": "uuid",
  "flow_id": "24-hex",
  "verdict": "C2",
  "confidence": "CONFIRMED",
  "note": "malware trace와 일치",
  "flow_snapshot": {},
  "created_by": "analyst",
  "created_at": "ISO-8601"
}
```

- `verdict`: `C2 | BENIGN`
- `confidence`: `CONFIRMED | HIGH | MEDIUM`
- 라벨은 원 Flow 핵심 필드와 비가역 Payload 특징 snapshot을 보존한다.
- 라벨은 수정/삭제하지 않고, 정정이 필요하면 새 라벨을 추가한다. 가장 최근 라벨을
  현재 판정으로 사용한다.
- `BENIGN` 라벨과 exact Payload hash가 같은 활성 signature 생성은 충돌로 거부한다.

## 7. Signature 모델과 생명주기

```json
{
  "id": "uuid",
  "name": "family-x UDP beacon",
  "description": "분석가가 확인한 초기 beacon",
  "version": 1,
  "enabled": true,
  "source_job_id": "uuid",
  "source_flow_id": "24-hex",
  "source_label_id": "uuid",
  "protocol": "UDP",
  "direction": "OUTBOUND",
  "service_port": 443,
  "payload_hash": "sha256",
  "payload_prefix_hash": "sha256",
  "payload_length": 48,
  "payload_entropy": 6.2142,
  "payload_printable_ratio": 0.125,
  "payload_simhash": "0123456789abcdef",
  "length_tolerance_ratio": 0.15,
  "entropy_tolerance": 0.75,
  "simhash_max_distance": 8,
  "created_at": "ISO-8601",
  "updated_at": "ISO-8601"
}
```

- 생성 시 source Flow의 protocol, direction, 외부 service port를 기본 guard로 사용한다.
- `enabled=false`는 탐지에서 제외하지만 provenance와 과거 결과는 유지한다.
- 조건 변경은 `version`을 증가시키며 기존 분석 snapshot에는 영향을 주지 않는다.
- signature는 monitor/alert용이다. 별도 검증 없이 block rule로 승격하지 않는다.

## 8. Match 판정

### 8.1 공통 guard

- Flow의 한쪽은 `internal_networks` 내부, 다른 쪽은 외부여야 한다.
- protocol은 같아야 한다.
- signature에 service port가 있으면 외부 상대의 service port가 같아야 한다.
- signature에 direction이 있으면 Flow direction이 같아야 한다.

### 8.2 EXACT

`payload_hash`가 같으면 `EXACT`다.

- Evidence confidence: `1.0`
- 기본 contribution/cap: `80`
- 단일 내부 호스트 감점은 적용하지 않는다.
- 결과 action: `alert`

### 8.3 STRUCTURAL

exact가 아니고 다음을 모두 만족하면 `STRUCTURAL`이다.

1. `payload_prefix_hash` 일치 또는 SimHash Hamming distance `<= 8`
2. 길이 차이가 `max(16 bytes, source_length × 15%)` 이하
3. entropy 차이가 `<= 0.75`
4. 비교 가능한 Payload 특징이 3개 이상

- Evidence confidence: `0.7`
- 기본 contribution/cap: `60`
- 단일 내부 호스트 감점은 유지한다.
- 결과 action: `monitor`

모든 Evidence metrics에는 비교한 필드, Hamming distance, 길이/entropy 차이,
signature ID/version, match mode를 포함한다.

## 9. 기존 탐지 개선

1. New Analysis UI 기본값을 hunting에 맞게 `minimum score=20`,
   `minimum internal hosts=3`으로 조정한다.
2. 단일 호스트라도 아래 복합 조건이면 `SINGLE_HOST_BEACON` Evidence를 생성한다.
   - 최소 5회 이상
   - interval CV `<= 0.30`
   - 동일 Payload hash 비율 `>= 0.60` 또는 packet-size CV `<= 0.20`
   - 평균 packet count `<= 10`
3. 이 Evidence contribution/cap은 `35`이며 기존 단일 호스트 감점 후에도 LOW candidate로
   남아 hunting 목록에서 확인할 수 있어야 한다.
4. 공용 DNS/NTP, CDN/cloud 감점은 기존대로 유지한다.

## 10. API

| Method | Path | 목적 |
|---|---|---|
| `GET` | `/analysis-jobs/{job_id}/flows` | bounded Flow 조회/필터 |
| `GET` | `/analysis-jobs/{job_id}/flows/{flow_id}/payload-preview` | PCAP Payload 미리보기 |
| `POST` | `/analysis-jobs/{job_id}/flow-labels` | 라벨 및 선택적 signature 생성 |
| `GET` | `/analysis-jobs/{job_id}/flow-labels` | Job 라벨 이력 |
| `GET` | `/payload-signatures` | signature 목록 |
| `PATCH` | `/payload-signatures/{signature_id}` | 이름/설명/활성 상태/threshold 수정 |

Flow 목록 필터는 `candidate_ip`, `direction`, `protocol`, `port`, `has_payload`를 지원하고
page size는 최대 200이다. Payload 미리보기는 최대 256 bytes이며 retained source PCAP이
없으면 `409 PAYLOAD_PREVIEW_UNAVAILABLE`을 반환한다.

## 11. UI

- Candidate 상세에 `Flow review` 표를 추가한다.
- Analysis 상세에 전체 Flow explorer를 추가해 Candidate가 없는 Flow도 endpoint,
  direction, protocol, 외부 service port, Payload 유무로 검색한다.
- 각 Flow는 시간, 방향, endpoint, protocol/port, packet/byte, Payload 특징, 현재 라벨을
  표시한다.
- `Preview payload`, `Mark C2 + create signature`, `Mark benign` 동작을 제공한다.
- 별도 `Payload signatures` 화면에서 활성화/비활성화와 provenance를 관리한다.
- EXACT/STRUCTURAL Evidence를 사람이 읽을 수 있는 설명과 원 비교값으로 표시한다.

## 12. 수용 기준

- `HGD-001`: 동일 Payload hash의 다른 외부 IP Flow가 exact signature로 Candidate가 된다.
- `HGD-002`: 소규모 byte 변형은 structural 조건을 충족하면 Candidate가 된다.
- `HGD-003`: protocol/port guard가 다른 Flow는 같은 Payload 특징이어도 일치하지 않는다.
- `HGD-004`: BENIGN exact conflict는 활성 signature로 생성되지 않는다.
- `HGD-005`: 비활성 signature는 새 분석에서 Evidence를 만들지 않는다.
- `HGD-006`: 라벨과 signature에 source job/flow 및 버전이 남는다.
- `HGD-007`: Payload 원문은 job, label, signature, audit에 저장되지 않는다.
- `HGD-008`: retained PCAP 미리보기는 256 bytes 이하이고 응답 외에는 보존되지 않는다.
- `HGD-009`: 기존 Flow는 payload hash만으로 exact signature가 동작한다.
- `HGD-010`: 완료 Job은 변경되지 않고 reanalysis에서 새 signature가 적용된다.
- `HGD-011`: 단일 호스트 복합 beacon은 LOW 이상 Candidate로 노출된다.
- `HGD-012`: 전체 기존 detector, PCAP, Worker, Web 회귀 테스트가 통과한다.
- `HGD-013`: Candidate로 승격되지 않은 Job Flow도 Analysis 상세에서 조회·라벨링할 수 있다.

## 13. 검증 및 운영 경계

- exact match는 분석가가 확인한 Payload 재관찰이라는 강한 근거지만 malware 실행이나
  공격 성공을 단독으로 증명하지 않는다.
- structural match는 반드시 monitor 상태로 시작하고 false-positive 검토 후 threshold를
  조정한다.
- 서비스별 정상 고정 Payload, health check, keepalive가 signature와 충돌할 수 있다.
- 암호화된 세션의 application Payload가 매 연결 달라지면 TLS fingerprint/domain과
  행위 탐지를 함께 사용한다.
- Sensor와 Controller가 서로 다른 feature version을 사용하면 structural match를
  중단하고 exact hash만 허용한다.
