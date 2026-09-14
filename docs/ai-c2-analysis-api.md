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

## 생성 초안

- `GET /ai-assessments/{assessment_id}/artifacts`
- `GET /ai-artifacts/{artifact_id}`
- `POST /ai-assessments/{assessment_id}/artifacts/regenerate`
- `POST /ai-artifacts/{artifact_id}/approve`
- `POST /ai-artifacts/{artifact_id}/reject`

조회는 VIEWER 이상, regenerate/approve/reject는 ANALYST 이상이다. review 요청은 `{"note":"..."}`를 사용한다. approve/reject는 `PENDING`에서 한 번만 전이하며 외부 Splunk 배포나 MISP publish를 수행하지 않는다.

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

### Network interpretation failure diagnostics (Step 4)

New `NETWORK_ANOMALY` runs rejected by `StructuredLocalGateway` after one repair
retain `MODEL_OUTPUT_INVALID` and the fixed message `Model output failed validation.`
They may additionally expose this closed, typed optional field on create/get/list/cancel
run responses (including OpenAPI). Existing run metadata remains extensible and is not
silently dropped. Old runs and gateways without diagnostic support omit this field;
absence does not identify the cause of a historical failure.

```json
{
  "failure_diagnostic": {
    "stage": "MODEL_OUTPUT",
    "type": "SCHEMA",
    "attempt_count": 2,
    "repair_count": 1,
    "output_bytes": 2,
    "provider_finish_reason": "stop"
  }
}
```

This example is produced by the deterministic test transport returning `{}` twice.
`type` is one of `JSON_PARSE`, `SCHEMA`, `INVALID_CITATION`, `LANGUAGE`. Citation
validation rejects unknown or duplicate issue IDs. Language validation checks the
response's `ko`/`en` language tag against the requested tag, not natural-language
identification of every prose field. The same authoritative validator runs inside
the gateway repair boundary and again before service publication; the latter never
invokes the model.

Counts describe completed output attempts (1–2) and repairs (0–1), with
`repair_count = attempt_count - 1`. `output_bytes` is the last rejected response's
UTF-8 length (replacement encoding for invalid Unicode surrogates), not raw text,
tokens, aggregate bytes or input length. The provider reason is included only when
actually present in Ollama `done_reason` or OpenAI-compatible
`choices[0].finish_reason`, and only for `stop`, `length`, `load`, `unload`,
`tool_calls`, `content_filter`; unknown/missing values are omitted. A finish reason
does not by itself prove why validation failed. No raw output, rejected field value,
dynamic key, Pydantic location or exception text is persisted, logged or added to
the network repair prompt. Repair receives the allowlisted category and fixed
instructions only, in addition to the original bounded input and schema.

There are at most **two completed model-output attempts**: initial generation plus
one repair. Existing transport retries remain bounded separately: `retries` 0–3
allows up to `retries + 1` HTTP attempts per generation, hence at most eight HTTP
attempts if both generations follow three failed transports. Invalid output itself
is never transport-retried; there is no outer service repair loop. A timeout may
have reached the provider, so these client-side bounds cannot guarantee how many
inferences a provider processed. Timeout, cancellation and unexpected transport
failure retain `MODEL_TIMEOUT`, `CANCELLED`, or `AI_ANALYSIS_FAILED`, respectively;
they do not acquire a misleading model-output diagnostic, even after a rejected
first output. Repaired successes publish only validated interpretation, without a
failure diagnostic. The deterministic report is unchanged in every case.

Invalid source projection is rejected before run creation/model I/O with
`AI_RUN_NOT_ALLOWED` and fixed `Network report input failed validation.` text; it
is not classified as model output. This feature does not diagnose or claim to fix
the earlier real Ollama failure. Deterministic fake-transport gateway/service/API/
SQLite-reopen tests establish these contracts; no live model execution is required.
