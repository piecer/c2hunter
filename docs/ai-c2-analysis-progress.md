# AI C2 Analysis 구현 진행

## Current phase

Milestone 1 완료 — FakeGateway 기반 안전한 수직 슬라이스

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

## Verification

2026-08-09 실제 실행 결과:

- AI/backend targeted tests: 33 passed
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

1. Ollama/OpenAI-compatible local model adapter, JSON repair 1회, timeout/retry/circuit breaker
2. 시계열 feature 확장과 Job-level sequence assessment
3. fingerprint graph와 campaign clustering
4. confidence calibration dataset/metrics/guardrail promotion
5. analyst feedback, calibration materialization, drift observability
6. 보존 기간 cleanup과 대규모 성능/부하 검증

각 후속 milestone도 schema/fixture부터 RED → GREEN → REFACTOR 순으로 진행한다.
