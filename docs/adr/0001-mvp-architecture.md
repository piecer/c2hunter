# ADR-0001: MVP 분산 아키텍처와 저장소 경계

- 상태: 승인(Proposed baseline)
- 날짜: 2026-07-20
- 결정자: C2Hunter 프로젝트
- 관련 명세: SPEC.md §4–5, §7–12, §14–19, §24–31

## 컨텍스트

C2Hunter MVP는 최소 두 Linux 센서가 NAT/방화벽 내부에서도 중앙 시스템과 통신하고, 100만 패킷 이상을 OOM 없이 처리하며, Flow/PCAP/분석 결과를 Web/API로 제공해야 한다. 센서 원격 제어, 재전송, 다중 센서 상관분석, 후보별 PCAP export, 설명 가능한 규칙 기반 점수, 장애 복구와 보관 정책도 필요하다.

단일 관계형 DB나 동기식 단일 프로세스는 구현은 간단하지만 대량 Flow, binary PCAP, 장시간 detector/export 작업, 독립 재시도 요구를 한 경계에 결합한다. 반대로 MVP부터 Kubernetes/마이크로서비스를 세분화하면 운영·테스트 비용이 과도하다.

## 결정

1. **센서는 Go로 구현**하고 Linux 운영 capture는 AF_PACKET/TPACKET_V3를 우선한다. 개발·fixture에는 libpcap/offline backend를 허용한다.
2. **Sensor→Controller outbound mTLS gRPC**만 사용한다. 센서가 만든 장기 연결에서 등록, heartbeat, 명령 수신, batch ACK를 처리하며 Controller의 센서 inbound 접속을 요구하지 않는다.
3. **중앙 제어는 Python 3.12+ FastAPI/Pydantic**, 비동기 실행은 Celery/Redis로 구현한다. API/Sensor Gateway는 MVP에서 한 배포 단위가 가능하지만 Analysis Worker는 별도 프로세스다.
4. **저장소를 용도별 분리**한다.
   - PostgreSQL: 센서, 사용자/RBAC, 작업 상태, idempotency/ingest ledger, 후보/evidence summary, allowlist, 감사
   - ClickHouse: Flow, 프로토콜 이벤트, time-series observation
   - MinIO: 회전 PCAP, filtered export, artifact
   - Redis: durable task 전달과 cache; 권위 상태는 아님
5. **Flow-first 전송**을 기본으로 하고 Payload 원문은 opt-in, 기본 비활성화한다. 선택 시 PCAP은 센서에서 회전해 object storage로 업로드한다.
6. **chunk/streaming 파이프라인**과 bounded queue를 강제한다. sensor batch ID와 DB ledger, immutable dataset/run snapshot으로 재시도·재분석을 멱등하게 한다.
7. detector는 공통 `Detector` 인터페이스로 독립 구현하고 Evidence를 산출한다. 최종 0~100 합산/감점은 별도 scoring 모듈이 담당한다.
8. React/TypeScript/Vite UI는 `/api/v1` REST만 사용한다. 모든 인증·인가의 권위는 API에 둔다.
9. 전체 MVP는 Docker Compose와 Make target으로 로컬/CI에서 재현한다. Kubernetes, TLS 복호화, ML 분류, 능동 기능은 제외한다.

## 결정 근거

- Go/AF_PACKET은 센서의 PPS·메모리 요구와 Linux 친화성이 높고 capture backend 교체가 가능하다.
- outbound gRPC stream은 NAT 환경과 typed contract, backpressure/ACK 구현에 적합하다.
- FastAPI/Celery는 API와 Python 분석 생태계(Polars/NumPy/SciPy)를 같은 타입/도메인 계층에 연결하되 긴 작업을 분리한다.
- PostgreSQL은 transactional state/idempotency에, ClickHouse는 time-range aggregation에, MinIO는 큰 immutable object에 적합하다.
- 물리적 마이크로서비스를 최소화하면서 논리적 포트/어댑터 경계를 유지해 MVP 속도와 향후 확장을 절충한다.

## 결과

### 긍정적 결과

- 센서 네트워크 위치와 무관하게 중앙 제어가 가능하다.
- API 재시작·worker redelivery·batch 재전송 후에도 DB 기반 멱등성을 유지할 수 있다.
- Flow query와 PCAP lifecycle이 분리되어 100만 패킷 benchmark를 streaming으로 최적화할 수 있다.
- detector와 score를 독립 테스트하고 각 근거를 사용자에게 설명할 수 있다.
- production과 offline 합성 PCAP가 같은 flow 계약을 공유한다.

### 비용/위험

- 네 종류의 인프라(PostgreSQL, ClickHouse, MinIO, Redis)를 운영해야 한다.
- 분산 상태와 eventual consistency, schema migration, object/metadata 정합성 처리가 필요하다.
- gRPC/REST/ClickHouse 간 스키마 버전 관리가 필요하다.
- Celery 작업 자체만으로 exactly-once가 보장되지 않으므로 모든 side effect에 멱등 ledger가 필요하다.

### 완화

- Docker Compose healthcheck와 `/ready`로 의존성 상태를 명시한다.
- protobuf/schema version과 호환성 테스트를 둔다.
- DB transaction의 상태 전이/ingest ledger, server-generated object key, checksum을 사용한다.
- 실패 injection 및 Controller/Redis/Worker/Sensor/MinIO/PostgreSQL 복구 통합 테스트를 둔다.

## 검토한 대안

### 단일 PostgreSQL에 Flow와 binary 저장

초기 구성은 단순하지만 대량 시계열 집계와 보관 삭제, binary 크기가 OLTP와 충돌한다. 테스트의 파일 기반 adapter는 허용하되 운영 기본으로 채택하지 않는다.

### 센서가 REST polling/upload만 사용

구현은 단순하지만 command latency, typed streaming, backpressure와 양방향 상태 전달이 약하다. NAT-safe outbound gRPC stream을 채택한다.

### Kafka 기반 event streaming

높은 확장성은 있으나 최소 2 sensor MVP에 운영 비용이 과도하다. Redis/Celery와 sensor file spool로 필수 복구를 충족하고 향후 queue adapter로 교체 가능하게 한다.

### 모든 기능을 하나의 Controller 프로세스에서 동기 실행

긴 ingestion/detection/export가 API 응답성과 장애 격리를 해친다. worker를 분리한다.

### 초기 ML classifier

설명 가능성·훈련 데이터·재현성 요구에 불리하고 명세 MVP 제외 대상이다. 규칙/통계 detector를 채택한다.

## 준수 확인

이 결정은 `TASKS.md`의 ARC/INF/SEN/ING/DET/SEC/PER/REC 요구 및 DoD와 연결된다. 변경 시 후속 ADR을 작성하고 데이터 모델, protobuf, API/OpenAPI, 테스트 및 운영 문서를 함께 갱신한다.
