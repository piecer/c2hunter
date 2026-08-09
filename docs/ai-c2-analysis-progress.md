# AI C2 Analysis 구현 진행

## Current phase

Phase 5 완료 — Validated Splunk/MISP Artifacts

## Completed

### Phase 0

- `AI_C2_ANALYSIS_SYSTEM.md`와 architecture/data-model/detection/human-guided 문서를 조사했다.
- 현재 PCAP → normalized Flow → Candidate → Evidence 저장/조회 경계와 Memory/SQLite/PostgreSQL adapter를 추적했다.
- `docs/adr/0002-local-ai-c2-analysis.md`에 경계, queue, 상태, 저장, 보안, rollback 결정을 기록했다.

### Milestone 1

- 엄격한 Pydantic Candidate Assessment schema와 구조화 `FakeGateway`를 구현했다.
- raw PCAP/payload를 제외하고 64 KiB 이하인 bounded Evidence Bundle을 기존 Candidate 근거에서 생성한다.
- 출력 schema와 모든 evidence reference를 검증하고 malformed output, timeout, prompt injection, 민감 키를 회귀 테스트한다.
- `QUEUED → PREPARING → ANALYZING → VALIDATING → COMPLETED/FAILED/CANCELLED` 전이 표, 진행률, terminal 불변성을 구현했다.
- Memory/SQLite/PostgreSQL에 별도 Run/Assessment 저장 객체, 원자적 idempotency, append-only 감사 이벤트를 구현했다.
- 독립 `c2hunter:ai:jobs` queue와 processing lease/recovery, AI worker entrypoint를 구현했다.
- create/list/detail/cancel Run API, assessment/evidence API와 역할 정책을 구현했다.
- Analysis 상세와 Candidate 상세에 실행, 상태, 진행률, verdict, confidence, 근거 ID 카드 UI를 구현했다.
- Compose `ai` profile, 기본 비활성 feature flag, API/운영/보안 문서를 추가했다.

### Phase 2

- Job 전체 Flow와 Candidate peer 관련 Flow를 분리 집계해 packet/byte/time/direction/protocol 요약을 생성한다.
- 누락 timestamp, unknown direction 비율, 제외된 payload 필드, 실패 Sensor와 clock warning을 data quality snapshot으로 보존한다.
- Candidate Flow의 domain, TLS/certificate fingerprint, TCP flag를 bounded protocol context로 변환한다.
- raw packet/payload는 Bundle에 포함하지 않고, UTF-8 byte 기반 보수적 estimator와 결정론적 reducer로 8,192 token 목표 상한을 지킨다.
- 파생 metadata를 제외한 canonical JSON에 SHA-256을 적용하며 같은 입력과 다른 dict key 순서는 같은 hash를 생성한다.
- 64 KiB 이하 Bundle은 Assessment JSONB에 inline 저장하고 bundle hash와 byte/token metadata를 함께 보존한다. 향후 상한을 넘는 artifact는 MinIO object storage 정책으로 확장한다.

### Phase 3

- 완료된 Job의 전체 external peer universe를 기존 Candidate와 독립적으로 집계한다.
- single-host beacon, payload cluster, synchronized cluster, robust volume anomaly를 가산하고 common service, high volume, trusted peer를 감점한다.
- 모든 factor는 이름, 가감점, 설명, metrics를 보존하며 `ai-prefilter-v1` 버전과 0~100 score를 생성한다.
- 기존 Candidate와 생성 후보를 결정론적으로 병합하고 상위 N개를 AI Run의 bounded candidate snapshot에 저장한다.
- 생성 후보는 기존 Candidate repository를 변경하지 않으며 worker Queue에는 계속 Run ID만 전달한다.
- AI-A~AI-J fixture와 31-peer recall fixture에서 알려진 beacon peer가 top 20에 포함되는 것을 검증한다.

### Phase 4

- 공통 gateway interface에 Ollama와 OpenAI-compatible provider를 구현하고 `fake`를 기본값으로 유지한다.
- prompt name/version/SHA-256, input/output schema version과 실제 provider/model을 AI Run에 snapshot한다.
- timeout과 transient retry, repository 상태 callback 기반 cancellation, model readiness를 구현했다.
- 모델 응답은 Pydantic schema, Candidate IP, Evidence ID, passive-only safety validator를 통과해야 저장한다.
- malformed JSON/schema는 원 오류를 bounded repair instruction으로 전달해 정확히 1회만 복구한다.
- OpenAI-compatible provider는 native `json_schema` response format을 사용한다. Ollama는 현재 backend의 complex grammar/output-budget 제약 때문에 normalized schema를 마지막 trusted prompt로 전달하고 JSON mode 후 동일 validator를 적용한다.
- 로컬 `qwen3.6-agent:256k` live smoke에서 후보 1개가 `INCONCLUSIVE`, confidence 0.3, `E-C2H-001` 근거로 검증됐다.

### Phase 5

- 고정 `c2hunter_flow_v1` profile에서 hunting SPL과 scheduled detection SPL을 결정론적으로 생성한다.
- write command, `index=*`, 시간 범위 누락, unknown profile field, Evidence에 없는 IP/hash literal을 거부한다.
- MISP draft는 `published=false`와 bounded attribute schema를 강제하고 unknown IOC, RFC1918 내부 IP, 역전된 시간 범위를 거부한다.
- Memory/SQLite/PostgreSQL에 별도 `ai_generated_artifacts` 저장 경계와 assessment index를 추가했다.
- list/detail/regenerate/approve/reject API를 추가했으며 review는 외부 publish/deploy 없이 terminal 상태와 감사 이벤트만 저장한다.
- Analysis UI에 raw JSON 대신 SPL code preview와 MISP publish 상태/IOC/attribute count 및 approve/reject를 구조화해 표시한다.

## Verification

2026-08-09 실제 실행 결과:

- AI/backend targeted tests: 19 passed (Phase 2 최신 targeted suite)
- controller/analysis mypy: passed
- web unit test: passed
- `make lint`: passed
- `make test`: passed
- `make build`: passed
- Playwright E2E: 7 passed (AI 실행 → Job 판정 → Candidate 판정 포함)
- `docker compose --env-file .env --profile ai config --quiet`: passed
- `docker compose --env-file .env --profile ai build ai-worker`: passed
- `git diff --check`: passed

## Remaining milestones

아래 작업은 명세의 후속 단계이며 Milestone 1 범위에 포함되지 않는다.

1. analyst feedback, calibration materialization, drift observability
2. 보존 기간 cleanup과 대규모 성능/부하 검증

각 후속 milestone도 schema/fixture부터 RED → GREEN → REFACTOR 순으로 진행한다.
