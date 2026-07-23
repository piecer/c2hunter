# C2Hunter MVP 아키텍처

## 1. 목적과 설계 원칙

C2Hunter는 복수 Linux 센서가 관찰한 트래픽을 하나의 분석 컨텍스트로 결합해 규칙·통계 기반으로 DDoS 봇넷 C2 후보를 설명 가능하게 식별한다. MVP의 핵심은 **두 센서 → 수집/저장 → 상관분석 → API/UI 결과 → 후보별 PCAP**의 완전한 수직 슬라이스다.

설계 원칙은 다음과 같다.

1. 센서는 NAT/방화벽 내부에서 Controller로만 아웃바운드 연결한다.
2. 원시 패킷 대신 Flow/프로토콜 메타데이터를 기본 전송하고, Payload 원문 저장은 기본 비활성화한다.
3. 패킷·Flow 처리는 chunk/streaming으로 제한 메모리에서 수행한다.
4. 제어 영역(PostgreSQL)과 대용량 Flow 영역(ClickHouse), 객체 영역(MinIO)을 분리한다.
5. 비동기 작업은 durable queue와 영속 상태 머신을 사용하며 재시도·멱등성·부분 성공을 명시한다.
6. detector, 저장소, 캡처 backend, 객체 저장소는 인터페이스 경계로 격리한다.
7. 모든 결과는 점수뿐 아니라 입력 지표, 관찰 센서/단말/시간, 오탐 근거, PCAP 참조를 보존한다.
8. 방어적 수동 분석만 수행하며 C2 접속·명령·스캔·공격 재현 기능을 두지 않는다.

## 2. 런타임 구성

```text
Browser
  │ HTTPS / REST (/api/v1)
  ▼
Web UI (React/TypeScript/Vite)
  │
  ▼
Controller API (FastAPI/Pydantic)
  ├── PostgreSQL: 사용자/센서/작업/후보/감사/정책
  ├── Redis: Celery broker/cache
  ├── ClickHouse: Flow/프로토콜 이벤트/관찰
  ├── MinIO: 회전 PCAP/후보 export/분석 산출물
  └── Celery Worker
       ├── ingestion pipeline
       ├── detector pipeline
       ├── score aggregation
       ├── PCAP export
       └── retention cleanup

Sensor A/B (Go)
  ├── AF_PACKET TPACKET_V3 capture (테스트: libpcap/offline PCAP)
  ├── direction classifier + flow aggregator + protocol metadata
  ├── rotating PCAP writer
  ├── file spool / backpressure
  └── outbound mTLS gRPC stream ───────────────► Sensor Gateway
```

MVP는 논리적 컴포넌트를 유지하되 Controller API와 Sensor Gateway를 같은 Python 배포 단위에 둘 수 있다. Analysis Worker는 별도 프로세스로 실행한다. 이는 독립 확장 경계를 유지하면서 운영 복잡도를 줄이는 선택이다.

## 3. 컴포넌트 경계와 책임

### 3.1 Sensor Agent (`sensor/`)

**소유 책임**
- YAML/환경변수 설정 검증, 인터페이스 탐색, 명시적 방향 분류
- AF_PACKET 기반 캡처, BPF/CIDR/port/protocol/IP version/direction 필터
- Flow key 집계, 60초 기본 idle timeout, 프로토콜 특징 추출
- 작업별 선택적 PCAP 회전(기본 1GB/5분), object upload
- 등록/10초 heartbeat, 명령 poll/양방향 stream, batch upload
- 메모리 queue → 디스크 spool → batch 축소 → 재시도 → 삭제/중지의 backpressure
- batch ID, 로컬 ACK 상태, 데이터 손실 통계

**비소유 책임**
- C2 점수 계산, allowlist 적용, 사용자 인증, 전역 센서 상관분석

캡처 backend는 `LiveCapture`(TPACKET_V3), `PcapCapture`(테스트/개발), `OfflineReader`로 분리하고 동일한 packet event를 flow 계층에 전달한다. 판별 근거가 없으면 방향은 반드시 `UNKNOWN`이다.

### 3.2 Sensor Gateway / Controller API (`controller/`)

**소유 책임**
- mTLS sensor identity와 Sensor 역할 검증, 등록/heartbeat/기능 협상
- 센서/그룹/태그/활성 상태 관리와 원격 작업 명령 발행
- `/api/v1` REST, OpenAPI, pagination/filtering/sorting
- 분석 요청 idempotency, 상태 머신, 권한(ADMIN/ANALYST/VIEWER/SENSOR)
- 감사 로그, 구조화 오류, health/readiness/metrics
- 저장소 접근 조정 및 signed download URL 발급

Controller가 센서에 직접 inbound 접속하지 않는다. 센서가 연 outbound gRPC stream에서 pending command를 수신하고 command 결과를 회신한다.

### 3.3 Ingestion (`analysis/pipeline/`)

- batch ID를 PostgreSQL ingest ledger에서 원자적으로 claim해 중복 재전송을 무해화한다.
- batch schema/version/checksum 검증 후 ClickHouse에 chunk insert한다.
- packet fingerprint 중복 제거 시 논리 packet/flow count는 한 번만 반영하되 모든 `sensor_observation`을 보존한다.
- 저장 성공 후 ACK하며, 실패 시 ACK하지 않아 센서 재전송이 가능하다.
- 작업별 ingest watermark와 누락/손실량을 기록한다.

### 3.4 Analysis Worker (`analysis/`)

- `AnalysisContext`는 job, time range, selected sensors, internal CIDRs, profile, thresholds, clock offsets, allowlist snapshot 및 chunked query interface를 제공한다.
- 각 detector는 `Detector.analyze(context) -> Iterable[Evidence]` 공통 계약을 구현한다.
- detector는 증거만 산출하고 최종 합산은 scoring 모듈이 수행한다.
- candidate IP 단위로 증거를 합산·감점하고 0~100 clamp 및 severity를 계산한다.
- 분석가가 승인한 활성 Payload signature의 job별 immutable snapshot을 exact/structural
  detector에 전달한다. 단일-host 복합 beacon과 analyst signature도 동일 Evidence/score
  계약을 사용한다.
- 동일 원천 데이터는 변경 불가능한 capture dataset으로 취급하며 재분석은 새 job/run과 파라미터 snapshot을 생성한다.

### 3.5 Web UI (`web/`)

UI는 REST API만 사용한다. TanStack Query로 서버 상태를 관리하고 하나의 컴포넌트 라이브러리를 일관되게 사용한다. Dashboard, Sensor, 분석 생성/진행, 후보 목록/상세, Flow review와 명시적 Payload 미리보기, C2/BENIGN 라벨, versioned Payload signature 관리, PCAP export, Allowlist 화면을 제공한다. 인증과 권한 판정의 권위는 서버에 있으며 UI 숨김만으로 권한을 구현하지 않는다.

### 3.6 저장소

| 저장소 | 권위 데이터 | 접근 주체 |
|---|---|---|
| PostgreSQL | identity, sensor/group, job/run/state transition, compact job metadata, immutable normalized job-flow payload, job별 Payload signature snapshot, flow label/signature provenance, candidate/evidence summary, allowlist, pcap object/export, audit, retention config, ingest ledger. Job metadata, job-flow JSONB, signature snapshot은 물리적으로 분리한다. | API/Worker |
| ClickHouse | flow, protocol metadata, time buckets, packet fingerprint 및 sensor observation | Worker/API read model |
| MinIO | raw uploaded/rotated PCAP, filtered export, benchmark/report artifact | Sensor/API/Worker |
| Redis | job-ID queue message, short-lived cache/lock; 분석 payload 원문은 저장하지 않음 | API/Worker |

Redis는 시스템 기록의 권위 저장소가 아니다. 작업 상태는 PostgreSQL이 권위이며 queue redelivery가 안전해야 한다. Controller의 목록·상세·스케줄러 경로는 compact metadata만 읽고, Worker가 분석을 시작할 때만 job ID로 immutable flow payload와 해당 job의 Payload signature snapshot을 로드한다.

## 4. 주요 데이터 흐름

### 4.1 센서 등록과 heartbeat

1. 센서는 인증서로 outbound mTLS gRPC 연결을 생성한다.
2. 등록 메시지의 Sensor ID와 인증서 identity를 결합해 고유성을 검증한다.
3. Controller는 기능/인터페이스/방향/시간/디스크/drop 정보를 저장한다.
4. 센서는 기본 10초마다 상태·자원·capture·queue·오류를 전송한다.
5. Controller는 수신 시각과 센서 시각 차이를 측정한다. 2초 초과 시 `DEGRADED`, 결과에 clock warning을 남긴다.
6. heartbeat timeout 시 `OFFLINE`으로 파생하되 마지막 보고 상태와 구분해 보존한다.

### 4.2 실시간 분석

1. ANALYST가 `idempotency_key`와 capture/analysis 조건으로 job 생성.
2. API가 센서/그룹, 시간, 필터, 한도를 검증하고 immutable parameter snapshot 생성.
3. 상태: `CREATED → WAITING_FOR_SENSOR → CAPTURING`.
4. 각 센서 outbound stream에 동일 job command를 전달한다.
5. 센서는 종료 조건 중 최초 충족까지 캡처하고 Flow batch/선택적 PCAP을 업로드한다.
6. 상태: `UPLOADING → INGESTING`; ingestion watermark가 완료되면 `ANALYZING`.
7. Controller는 payload가 아닌 job ID만 queue에 넣고, Worker가 PostgreSQL에서 해당 job의 immutable flow payload와 versioned signature snapshot을 한 번 로드해 detector와 scoring을 실행하고 후보/evidence를 저장한다.
8. 전 센서 성공은 `COMPLETED`, 일부 실패지만 분석 가능하면 `PARTIALLY_COMPLETED`, 분석 불능은 `FAILED`.
9. 모든 전환 시각·행위자·이유를 audit/state transition에 기록한다.

취소는 terminal state에 대한 멱등 명령이다. Controller는 pending/capturing 센서에 cancel을 전달하고 worker cooperative cancellation 후 `CANCELLED`로 수렴시킨다.

### 4.3 과거 데이터 재분석

기존 capture dataset/time range를 참조해 새 analysis run을 만든다. 원 Flow/PCAP은 복제하지 않고 profile/threshold/allowlist snapshot은 새로 고정한다. 원본 보관 만료로 불완전하면 요청 검증 또는 결과 warning으로 명시한다.

### 4.4 후보별 PCAP export

1. 권한·필터·최대 크기 검증 후 비동기 export 생성.
2. 관련 PCAP object 목록과 candidate/internal host/time/port/protocol/direction/sensor 필터를 정규화한다.
3. Worker가 object를 스트리밍 읽고 패킷을 스트리밍 필터링해 새 object로 multipart upload한다.
4. 완료 후 만료 signed URL을 발급한다. object key는 서버 생성 값만 사용하며 filename을 정화한다.
5. 요청·성공·다운로드를 감사 기록한다. 원본이 만료됐으면 UI/API가 명시한다.

## 5. 작업 상태 머신

```text
CREATED → WAITING_FOR_SENSOR → CAPTURING → UPLOADING → INGESTING → ANALYZING
   │              │                │           │           │          │
   └──────────────┴────────────────┴───────────┴───────────┴──────────┼→ FAILED
                                                                    ├→ COMPLETED
                                                                    └→ PARTIALLY_COMPLETED
비종료 상태 ──cancel──► CANCELLED
```

허용 전이는 서비스 계층 한 곳에서 검증하고 DB transaction 안에서 현재 상태 조건부 갱신과 transition/audit append를 함께 수행한다. 재시도는 같은 단계의 idempotent operation이며 상태를 역행시키지 않는다.

## 6. 신뢰성·성능

- Flow batch는 bounded 크기이며 ClickHouse bulk insert와 Polars lazy/streaming query를 사용한다.
- detector는 외부 IP/time bucket 파티션 단위로 처리하고 전체 패킷 materialization을 금지한다.
- 100만 패킷 benchmark는 wall time, peak RSS, 각 단계 처리량을 JSON/Markdown에 기록한다. 목표는 180초, Controller peak RSS < 8GB, OOM/데이터 손실 없음은 필수다.
- 센서 100,000 PPS/drop ≤1%는 목표치로 측정·기록한다.
- Celery task는 `acks_late`, bounded retry/backoff와 DB idempotency key를 사용해 worker/Redis/Controller 재시작을 견딘다.
- 대용량 job-flow payload와 signature snapshot은 compact metadata와 별도 저장하고 queue에는 reference만 전달한다. 상태 전환, 이력 조회, 완료된 UI 화면은 이를 재직렬화하거나 반복 polling하지 않는다.
- readiness는 PostgreSQL/Redis/ClickHouse/MinIO 연결을 검사하고 health는 프로세스 생존만 검사한다.
- cleanup은 작은 page 단위로 삭제하고 참조 PCAP 만료를 결과에 반영한다.

## 7. 보안·개인정보

- Sensor↔Controller mTLS, 사용자 API HTTPS, 인증서 만료·폐기 확인.
- 비밀은 환경변수/secret mount로 주입하며 저장소에 평문 비밀번호·개인키를 두지 않는다.
- RBAC를 API와 object download 모두에 적용한다.
- Pydantic/gRPC validation, 구조화 error code, object key allowlisting으로 입력 경계를 방어한다.
- Payload 저장 opt-in, 기본 hash/statistics-only. 실제 운영 PCAP은 저장소/테스트 fixture에 포함하지 않는다.
- 로그인, 작업, export/download, allowlist, sensor, 설정, 권한, 삭제를 append-only audit로 기록한다.

## 8. 관측성

모든 서비스는 `timestamp, level, service, component, job_id, sensor_id, request_id, message, error` 필드의 JSON 로그를 사용한다. `/metrics`는 명세의 packet/drop/flow/spool/job/duration/candidate/storage/queue/API latency 지표를 Prometheus 형식으로 노출한다. request/job/sensor ID를 로그·task·DB transition에 전파한다.

## 9. 배포와 검증 경계

Docker Compose는 최소 controller, worker, web, sensor-a, sensor-b, PostgreSQL, Redis, ClickHouse, MinIO를 포함한다. 개발용 인증서와 합성 데이터는 setup/generator가 로컬 생성하며 비밀을 커밋하지 않는다. 필수 Make target 및 최종 검증 순서는 `TASKS.md`의 `CMD-*`, `VAL-*`가 단일 권위다.

## 10. MVP 이후 확장점

캡처 backend, `Detector`, flow repository, object repository, queue adapter 인터페이스를 통해 고속 캡처·분산 worker·다른 object store를 추가할 수 있다. MVP에는 TLS 복호화, ML 분류, 능동 스캔/접속, Kubernetes, 장기 빅데이터 클러스터를 구현하지 않는다.
