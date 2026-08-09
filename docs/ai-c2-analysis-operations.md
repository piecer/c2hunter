# AI C2 Analysis 운영 가이드

## Milestone 1 실행

기본값은 비활성이다. FakeGateway 수직 슬라이스를 실행하려면 `.env`에 다음을 설정한다.

```bash
# AI Run API를 활성화한다.
C2HUNTER_AI_ANALYSIS_ENABLED=true
```

AI worker profile과 전체 서비스를 시작한다.

```bash
# 기존 서비스와 분리된 AI worker를 opt-in으로 시작한다.
docker compose --env-file .env --profile ai up -d --build
```

AI worker는 `c2hunter:ai:jobs`만 소비하며 기존 `c2hunter:analysis:jobs`를 사용하지 않는다. 메시지는 Run ID만 포함한다. Worker는 DB snapshot을 읽고 terminal Run이면 그대로 ack하므로 재전달에 멱등적이다. processing list와 lease 만료 복구를 사용한다.

## 장애 격리

- `C2HUNTER_AI_ANALYSIS_ENABLED=false`로 Controller의 AI Run 생성을 즉시 중지할 수 있다.
- AI worker 중지/장애는 기존 Analysis Job 상태와 Candidate를 바꾸지 않는다.
- 모델 timeout은 AI Run만 `FAILED/MODEL_TIMEOUT`으로 만든다.
- schema/evidence validator 실패는 AI Run만 `FAILED/MODEL_OUTPUT_INVALID`로 만든다.
- Queue 재전달은 terminal Run 불변성과 assessment ID upsert로 중복 결과를 만들지 않는다.

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

Milestone 1은 deterministic FakeGateway만 배치한다. Ollama/OpenAI-compatible local gateway, SPL/MISP draft, low-score universe 및 advanced protocol context는 후속 Phase에서 추가한다.
