# ADR 0002: 로컬 AI C2 분석 수직 슬라이스

- 상태: Accepted
- 날짜: 2026-08-09
- 기준 명세: `AI_C2_ANALYSIS_SYSTEM.md`

## 배경

C2Hunter의 Analysis Job은 packet/flow 정규화와 결정론적 탐지 결과를 소유한다. 완료된 Job과 Candidate는 재현성을 위해 AI 처리와 독립적으로 유지해야 한다. 로컬 모델은 탐지 엔진이 아니라, 이미 선택된 후보와 bounded evidence를 해석하는 보조 계층이다.

## 현재 저장·조회 경로

1. PCAP Upload는 Controller의 `/api/v1/pcap-analysis-jobs`에서 제한을 검증하고 `parse_pcap`으로 Flow를 정규화한다.
2. 원본 upload PCAP은 `Repository.save_job_capture` 경계를 통해 저장된다. Memory/SQLite는 byte blob, PostgreSQL은 MinIO `captures/{job_id}.pcap` 객체를 사용한다.
3. normalized Flow는 `job_flow_records` 경계에 저장된다. PostgreSQL은 약 8 MiB JSONB chunk인 `job_flow_record_chunks`를 사용한다.
4. Worker 결과 Candidate는 `Repository.save_candidates`로 Job별 저장된다. Candidate 내부 `evidence`가 기존 결정론적 탐지 근거다.
5. 조회는 Analysis Job 상세, `/analysis-jobs/{job_id}/flows`, `/analysis-jobs/{job_id}/candidates`, Candidate 상세 API를 사용한다.
6. ClickHouse `FlowStore`는 sensor batch의 durable ingest 경계다. PCAP upload의 normalized Flow snapshot은 Job repository 경계에 유지된다.

## 조사 시점의 명세와 구현 차이

- 별도 `ai/` package, AI queue/worker, AI Run schema/API/UI가 없었다.
- Alembic 같은 외부 migration framework는 없다. SQLite/PostgreSQL repository 초기화 시 additive DDL과 데이터 이동을 실행한다.
- PostgreSQL만 `audit_events`를 사용했고 Memory/SQLite에는 공용 audit 기록 계약이 없었다.
- 기존 Controller queue는 분석 Job/worker result 전용 양방향 경계다. AI 작업은 별도 key와 상태 머신이 필요하다.
- Candidate Evidence에는 현재 전역 고유 evidence ID가 보장되지 않는다.

## 결정

### 1. 불변 경계

AI Run은 Analysis Job 및 Candidate를 수정하지 않는다. Run 생성 시 다음을 snapshot한다.

- source Analysis Job ID 및 dataset ID
- 상위 Candidate ID 목록(기본/최대 5)
- provider/model/prompt/schema version과 prompt hash
- candidate limit 및 실행 config

완료 Run은 변경하지 않는다. 재실행은 새 Run을 만든다. 취소는 terminal 상태가 아닌 Run에만 적용한다.

### 2. package 경계

첫 수직 슬라이스의 AI domain/gateway/validator/evidence builder/service는 Controller와 독립적인 `c2hunter_controller.ai_analysis` 모듈에 둔다. 이유는 기존 Repository, auth, Candidate/Flow 조회 경계를 복제하지 않고 안전한 계약을 먼저 고정하기 위해서다. 별도 장기 실행 worker와 실제 Ollama adapter를 추가할 때 `ai/` deployable package로 분리한다. 이 임시 배치는 import 방향을 단방향으로 유지하며 모델 gateway가 Controller internals에 의존하지 않도록 한다.

### 3. 저장

세 adapter 모두 AI Run과 Assessment를 별도 객체로 저장한다.

- Memory: 별도 dictionary
- SQLite: `ai_analysis_runs`, `ai_candidate_assessments`, `ai_run_idempotency`
- PostgreSQL: 같은 이름의 JSONB table과 additive startup migration

Evidence Bundle은 Assessment에 versioned snapshot으로 저장하되 raw PCAP을 포함하지 않고 JSON serialized size를 제한한다.

### 4. 실행과 queue

Phase 1은 `AIAnalysisService`와 주입 가능한 `AIAnalysisTaskQueue` 경계를 둔다. 테스트의 `InlineAIAnalysisTaskQueue`는 FakeGateway로 즉시 실행해 네트워크 없는 결정적 통합 테스트를 제공한다. 운영은 `RedisAIAnalysisTaskQueue`와 독립 `ai-worker`가 별도 `c2hunter:ai:jobs`/processing/lease key를 사용한다. 기존 analysis queue key는 절대 재사용하지 않는다.

### 5. 보안과 검증

- Run 생성/취소: ANALYST 이상, 일반 GET: VIEWER 이상, Evidence Bundle GET: ANALYST 이상
- source Job은 `COMPLETED` 또는 `PARTIALLY_COMPLETED`여야 한다.
- 후보는 score 내림차순 상위 1~5개만 snapshot한다.
- bundle에는 raw capture/전체 packet hex를 넣지 않는다.
- 모든 model output은 Pydantic schema와 supplied evidence ID 집합으로 검증한 뒤에만 저장한다.
- captured 문자열은 evidence data이며 prompt instruction으로 취급하지 않는다.
- malformed output, timeout, validator 실패는 Run을 `FAILED`로 만들고 기존 Analysis 상태에는 영향을 주지 않는다.

## 상태 머신

`QUEUED -> PREPARING -> ANALYZING -> VALIDATING -> COMPLETED`

비 terminal 상태에서 `CANCELLED`, 실행 오류에서 `FAILED`로 전이할 수 있다. `COMPLETED`, `FAILED`, `CANCELLED`는 terminal이며 이후 변경하지 않는다.

## 변경 계획

1. schema/domain/FakeGateway와 validator 단위 테스트
2. migration/repository와 idempotency 테스트
3. service/queue와 상태 전이/취소 테스트
4. create/list/detail/cancel/assessment API 통합 테스트
5. bounded Evidence Bundle 및 prompt-injection fixture 테스트
6. Analysis 상세 실행/상태 UI와 Candidate 상세 assessment UI 테스트
7. lint/test/build/E2E 및 rollback 문서 검증

## 위험과 완화

- 큰 Evidence Bundle: candidate 5개, 목록/문자열 길이, JSON byte size를 hard limit한다.
- 중복 실행: `(analysis_job_id, idempotency_key)`를 유일하게 저장한다.
- 부분 저장: Run 상태와 Assessment 저장을 repository lock/transaction 경계에서 수행한다.
- worker 재전달: terminal Run은 재실행하지 않는 멱등 service 계약을 테스트한다.
- model 장애: gateway 예외를 Run error code로 변환하고 원본 Job/Candidate를 수정하지 않는다.
- PostgreSQL rollback: 신규 table은 기존 table을 참조만 하므로 기능 비활성화 후 `ai_candidate_assessments`, `ai_analysis_runs` 순서로 drop할 수 있다. 데이터 보존이 필요하면 먼저 JSON export한다. 감사 이벤트는 자동 삭제하지 않는다.

## 결과

첫 milestone은 FakeGateway 기반 안전한 수직 슬라이스를 제공한다. 실제 모델 품질, anomaly 후보, Splunk/MISP 배포, RAG, 자동 실행은 후속 ADR 없이 이 경계를 우회해 추가하지 않는다.
