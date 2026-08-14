# AI C2 Analysis 구현 진행

## Current phase

Phase 8 완료 — TI enrichment와 analyst response workflow

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

### Phase 6

- AI Run candidate limit, review-priority 정렬, AI verdict/analyst-confirmed verdict 분리 UI를 구현했다.
- append-only feedback ledger를 Memory/SQLite/PostgreSQL에 저장하고 VIEWER 읽기, ANALYST/ADMIN 쓰기 권한을 적용했다.
- feedback 작성과 history 표시를 Vitest 및 Playwright analyst workflow로 검증했다.

### Phase 7

- AI-A~AI-J Flow fixture를 candidate generation → Evidence Builder → FakeGateway → strict validation → artifact pipeline으로 실행해 Recall/Precision@20, rank/reduction, verdict/calibration/safety, stage/resource/token을 계산한다.
- `make test-ai`, `make evaluate-ai`, `make benchmark-ai` 명령과 JSON/Markdown report를 추가했다.
- provider/model/config/prompt/output-schema/bundle hash exact key를 사용하는 strict-validation 후 bounded LRU assessment cache를 추가했다.
- Controller enqueue/waiting/feedback과 Worker inference/processing/failure/schema-invalid를 의미별로 분리한 Prometheus scrape path를 추가했다.
- Analysis Job 삭제 시 active AI Run을 거부하고 terminal Run의 feedback → artifact → assessment → run을 Memory/SQLite/PostgreSQL transaction에서 cascade한다.
- AI table backup/restore 검증과 report 안전성 절차를 운영 문서에 추가했다.

### Phase 8

- VirusTotal/AbuseIPDB 후보 enrichment를 timeout, 직렬 single-flight, configurable pacing, bounded worker/queue와 함께 추가했다.
- analyst allowlist와 후보 terminal 상태를 보존하면서 단건/일괄 triage 및 enrichment history를 저장한다.
- AI가 생성한 MISP artifact는 `published=false` draft와 review 상태만 저장한다. 별도 Candidate MISP export는 ADMIN의 명시적 요청에 따라 외부 MISP에 attribute를 추가하며 감사 이력을 남긴다.
- TI 요청 gate는 shutdown cancellation과 nested/reentrant 호출을 회귀 테스트하며 설정·API·Web UI가 동일한 pacing 값을 사용한다.
- Ollama/OpenAI-compatible endpoint URL을 검증하고 public host 사용 시 Evidence metadata의 외부 전송을 Controller와 AI Worker startup warning으로 알린다.

## Verification

2026-08-09 실제 실행 결과:

- `make test-ai`: 59 passed
- `make lint`: Ruff, formatting, mypy, Go vet, ESLint passed
- `make test`: controller/analysis 355 passed, storage integration 1 skipped; worker 12 passed; Web 64 passed
- `make build`: Python compile, Go/Web build, sensor tarball, Controller/Worker/Web Docker build passed
- `make test-e2e`: Playwright 7 passed
- `make evaluate-ai`: baseline precision 0.6, recall 1.0, F1 0.75; conservative precision 0.6667, recall 1.0, F1 0.8
- `make benchmark-ai`: 100 iterations, 1,000 case evaluations, p50 20.52 ms, p95 21.61 ms, peak traced memory 13,344,640 bytes
- `git diff --check`: passed

## Remaining milestones

Phase 0~8 실행 계약을 완료했다. 실제 운영 model profile 변경은 새 평가 report, analyst feedback calibration 검토, capacity benchmark, rollback 기준을 함께 승인한 뒤 수행한다. TI/MISP는 provider quota, 조직 데이터 반출 정책, retry/soak 결과를 별도로 승인한 뒤 활성화한다.
