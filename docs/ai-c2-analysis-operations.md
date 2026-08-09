# AI C2 Analysis 운영 가이드

## Milestone 1 실행

기본값은 비활성이다. FakeGateway 수직 슬라이스를 실행하려면 `.env`에 다음을 설정한다.

```bash
# AI Run API를 활성화한다.
C2HUNTER_AI_ANALYSIS_ENABLED=true
# 실제 로컬 Ollama를 사용한다. fake는 deterministic test 기본값이다.
C2HUNTER_AI_MODEL_PROVIDER=ollama
C2HUNTER_AI_MODEL_BASE_URL=http://host.docker.internal:11434
C2HUNTER_AI_MODEL_NAME=qwen3.6-agent:256k
```

AI worker profile과 전체 서비스를 시작한다.

```bash
# 기존 서비스와 분리된 AI worker를 opt-in으로 시작한다.
docker compose --env-file .env --profile ai up -d --build
```

AI worker는 `c2hunter:ai:jobs`만 소비하며 기존 `c2hunter:analysis:jobs`를 사용하지 않는다. 메시지는 Run ID만 포함한다. Worker는 DB snapshot을 읽고 terminal Run이면 그대로 ack하므로 재전달에 멱등적이다. processing list와 lease 만료 복구를 사용한다.

AI worker는 시작 시 provider의 model 목록을 조회해 readiness를 확인한다. 모델이 없거나 endpoint가 닫혀 있으면 Queue를 소비하기 전에 종료한다. OpenAI-compatible endpoint는 필요할 때 `C2HUNTER_AI_MODEL_API_KEY`를 secret manager로 주입한다.

## 장애 격리

- `C2HUNTER_AI_ANALYSIS_ENABLED=false`로 Controller의 AI Run 생성을 즉시 중지할 수 있다.
- AI worker 중지/장애는 기존 Analysis Job 상태와 Candidate를 바꾸지 않는다.
- 모델 timeout은 AI Run만 `FAILED/MODEL_TIMEOUT`으로 만든다.
- schema/evidence validator 실패는 AI Run만 `FAILED/MODEL_OUTPUT_INVALID`로 만든다.
- HTTP timeout은 설정된 횟수만 재시도한 뒤 AI Run만 `FAILED/MODEL_TIMEOUT`으로 만든다.
- 실행 중 취소는 gateway retry/repair 경계에서 repository의 최신 `CANCELLED` 상태를 확인한다.
- Queue 재전달은 terminal Run 불변성과 assessment ID upsert로 중복 결과를 만들지 않는다.

## High-Recall prefilter

- prefilter는 기존 detector score를 수정하지 않는 결정론적 보조 rank다.
- `ai-prefilter-v1` factor와 score는 AI Run candidate snapshot에만 저장한다.
- common DNS/NTP, bulk transfer, trusted peer penalty는 LLM 호출 전에 적용된다.
- Flow가 없으면 기존 Candidate만 사용하고, 기존 Candidate가 없어도 적합한 external peer가 있으면 AI Run을 생성할 수 있다.

## Splunk/MISP 초안

- 완료된 assessment마다 `SPLUNK_HUNT`, `SPLUNK_DETECTION`, `MISP_DRAFT` 3개를 생성한다.
- SPL은 read-only profile validator, MISP는 unpublished/IOC/internal-IP validator를 통과한 경우만 저장한다.
- 승인과 거절은 조사 workflow 상태이며 외부 시스템 전송을 의미하지 않는다.
- regenerate는 새 PENDING artifact ID를 만들고 이전 review 이력을 덮어쓰지 않는다.

## 확인

```bash
# Compose 구성이 유효한지 확인한다.
docker compose --env-file .env --profile ai config --quiet

# worker 상태를 확인한다.
docker compose --env-file .env --profile ai ps ai-worker

# AI 전용 테스트를 실행한다.
.venv/bin/pytest -q controller/tests/test_ai_analysis.py controller/tests/test_ai_analysis_api.py controller/tests/test_ai_worker.py
```

## DB migration/rollback

Controller 시작 시 additive `CREATE TABLE IF NOT EXISTS`로 다음 객체를 만든다.

- `ai_analysis_runs`
- `ai_candidate_assessments`
- Job/Run 및 Run/assessment 조회 index

rollback은 먼저 `C2HUNTER_AI_ANALYSIS_ENABLED=false`로 신규 요청을 중지하고 AI worker를 내린 뒤, 보존 정책에 따라 백업 후 다음 순서로 수행한다.

```sql
-- AI 전용 데이터만 제거한다. 기존 Analysis Job/Candidate 테이블은 건드리지 않는다.
DROP TABLE IF EXISTS ai_candidate_assessments;
DROP TABLE IF EXISTS ai_analysis_runs;
```

SQLite도 같은 이름의 두 테이블과 index를 제거한다. 감사 이벤트는 보존 의무 때문에 rollback 시 자동 삭제하지 않는다.

## 현재 제한

Ollama structured grammar는 backend/model 조합에 따라 복잡한 schema와 큰 output budget을 동시에 거부할 수 있다. 현재 Ollama adapter는 normalized schema를 마지막 trusted instruction으로 전달하고 JSON mode 출력에 동일한 strict validator를 적용한다. OpenAI-compatible adapter는 native `json_schema`를 사용한다. SPL/MISP draft는 후속 Phase에서 추가한다.
