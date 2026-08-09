# AI C2 Analysis API

모든 경로는 `/api/v1` 기준이다. AI 기능은 `C2HUNTER_AI_ANALYSIS_ENABLED=true`일 때만 Run 생성이 가능하다.

## Run 생성

`POST /analysis-jobs/{job_id}/ai-runs`

요청:

```json
{
  "idempotency_key": "analyst-generated-key",
  "candidate_limit": 5
}
```

- ANALYST 이상
- 원본 Analysis Job 상태가 `COMPLETED` 또는 `PARTIALLY_COMPLETED`여야 한다.
- 기존 Candidate와 전체 Flow universe의 prefilter 생성 후보를 병합해 상위 5개를 bounded immutable snapshot으로 저장한다.
- 생성 후보는 `prefilter_score`, `prefilter_score_version`, explainable factor를 가지며 기존 Candidate 저장소를 변경하지 않는다.
- 최초 요청은 `201`, 같은 Job/key 재요청은 기존 Run과 `200`을 반환한다.
- 운영 Redis 모드에서는 `QUEUED`로 반환하고 `c2hunter:ai:jobs` 전용 Queue가 처리한다.
- isolated test의 memory Redis 모드는 같은 task 경계를 inline 실행한다.

## 조회

- `GET /analysis-jobs/{job_id}/ai-runs`
- `GET /ai-runs/{run_id}`
- `GET /ai-runs/{run_id}/assessments`
- `GET /ai-assessments/{assessment_id}`
- `GET /ai-assessments/{assessment_id}/evidence-bundle`

Evidence Bundle 조회는 ANALYST 이상이며 감사 이벤트를 남긴다. Bundle은 8,192 estimated token 및 64 KiB 이하이고 raw PCAP/payload/packet hex 계열 필드를 재귀적으로 제외한다.

## 취소

`POST /ai-runs/{run_id}/cancel`

```json
{
  "reason": "operator request"
}
```

terminal Run의 취소 요청은 상태를 바꾸지 않는 idempotent 응답이다. 완료/실패/취소 상태는 저장소에서 불변이다.

## 상태와 오류

상태: `QUEUED`, `PREPARING`, `ANALYZING`, `VALIDATING`, `COMPLETED`, `FAILED`, `CANCELLED`.

대표 오류:

- `AI_ANALYSIS_DISABLED` (503)
- `AI_RUN_NOT_ALLOWED` (409)
- `AI_RUN_NOT_FOUND` (404)
- `AI_ASSESSMENT_NOT_FOUND` (404)
- Run 내부 `error_code`: `MODEL_TIMEOUT`, `MODEL_OUTPUT_INVALID`
