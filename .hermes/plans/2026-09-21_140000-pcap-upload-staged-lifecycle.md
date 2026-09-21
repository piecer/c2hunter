# PCAP Upload Staged Lifecycle Implementation Plan

> **For Hermes:** Execute this plan task-by-task with strict RED→GREEN TDD and independent review before completion.

**Goal:** Return control to the operator immediately after durable PCAP acceptance and expose truthful upload, preparation, queue, analysis, and terminal states in the Web UI.

**Architecture:** Split job metadata creation from binary upload. Persist the immutable capture and a durable preparation intent before returning `202`; a lease-based preparation worker parses and stores flow records, then enqueues the existing analysis worker. Preserve the existing coarse `status` for compatibility and add a closed `processing.phase` contract for truthful PCAP-specific presentation. Browser upload progress uses XHR; unknown-duration server work uses an indeterminate stepper rather than fabricated percentages.

**Tech Stack:** FastAPI/Pydantic, Memory/SQLite/PostgreSQL repositories, Redis analysis queue, React 19/TanStack Query, Vitest/Playwright.

---

## Contract

User-visible phases:

1. `UPLOAD_PENDING`
2. `UPLOADING`
3. `UPLOAD_STORED`
4. `PARSING`
5. `ANALYSIS_QUEUED`
6. `ANALYSIS_RUNNING`
7. `FINALIZING`
8. `COMPLETED`, `PARTIALLY_COMPLETED`, `FAILED`, or `CANCELLED`

Upload transport progress is client-local. XHR 100% is labelled “전송 완료 · 서버 저장 확인 중”; only the server-persisted `UPLOAD_STORED` phase is labelled “업로드 완료”.

## Task 1: Freeze lifecycle contract and repository storage

**Files:**
- Modify: `controller/src/c2hunter_controller/schemas.py`
- Modify: `controller/src/c2hunter_controller/repositories.py`
- Modify: `controller/src/c2hunter_controller/production.py`
- Test: `controller/tests/test_analysis_history_pcap_api.py`
- Test: `controller/tests/test_storage_integration.py`

**TDD:**
1. Add failing tests for metadata-only job creation, closed processing phases, durable preparation admission, lease claim, retry, and terminal persistence.
2. Run focused tests and confirm failures are caused by missing contracts.
3. Add the minimum repository/API models and lease-safe storage.
4. Re-run focused tests.

## Task 2: Split create and upload acceptance

**Files:**
- Modify: `controller/src/c2hunter_controller/app.py`
- Modify: `controller/src/c2hunter_controller/jobs.py`
- Test: `controller/tests/test_analysis_history_pcap_api.py`

**TDD:**
1. Add a failing API test proving `POST /pcap-analysis-jobs` returns a job ID before bytes are sent.
2. Add a failing API test proving `PUT /pcap-analysis-jobs/{id}/capture` returns `202` only after immutable storage and durable preparation admission.
3. Add digest/idempotency/conflict and storage/admission rollback tests.
4. Implement the two endpoints while retaining the legacy binary POST as a compatibility wrapper until callers migrate.
5. Re-run focused tests.

## Task 3: Durable PCAP preparation worker

**Files:**
- Create: `controller/src/c2hunter_controller/pcap_preparation_worker.py`
- Modify: `controller/src/c2hunter_controller/app.py`
- Modify: `controller/src/c2hunter_controller/repositories.py`
- Modify: `controller/src/c2hunter_controller/production.py`
- Test: `controller/tests/test_pcap_preparation_worker.py`

**TDD:**
1. Add failing tests for claim→parse→flow persistence→analysis enqueue.
2. Add restart/lease-expiry, duplicate claim, malformed capture, packet limit, cancellation, and retry exhaustion tests.
3. Implement a bounded lease worker using the retained capture stream and existing parser.
4. Keep structural/posting indexing best-effort and non-blocking for analysis acceptance.
5. Re-run focused tests.

## Task 4: Truthful analysis start/finalization events

**Files:**
- Modify: `sensor/worker/src/c2hunter_worker/runtime.py`
- Modify: `sensor/worker/src/c2hunter_worker/queue.py`
- Modify: `controller/src/c2hunter_controller/app.py`
- Test: `sensor/worker/tests/test_runtime.py`
- Test: `controller/tests/test_local_analysis_runtime.py`

**TDD:**
1. Add failing tests proving queue admission remains `ANALYSIS_QUEUED`.
2. Add a worker start event and prove only that event produces `ANALYSIS_RUNNING`.
3. Add finalizing/terminal race tests so cancellation or duplicate events cannot overwrite an established terminal state.
4. Re-run focused tests.

## Task 5: Web upload progress and lifecycle stepper

**Files:**
- Modify: `web/src/api.ts`
- Modify: `web/src/App.tsx`
- Modify: `web/src/styles.css`
- Test: `web/tests/App.test.tsx`
- Test: `web/e2e/workflow.spec.ts`

**TDD:**
1. Add failing runtime tests for metadata creation, XHR byte progress, 100%-sent wording, durable upload acceptance, navigation, refresh recovery, and error rendering.
2. Implement an upload client with abort-safe XHR progress.
3. Add an accessible four-step upload/preparation/analysis/completion stepper to upload and job detail views.
4. Keep raw transitions available as expandable detail.
5. Add narrow-width and keyboard coverage.

## Task 6: Compatibility, operations, and verification

**Files:**
- Modify: `docs/detection-logic.md` or relevant API/operations documentation
- Modify tests/fixtures only where the producer contract changed.

**Verification:**
1. Focused controller, worker, Web unit, and Playwright tests.
2. `make test`
3. `make lint`
4. `make build`
5. `git diff --check`
6. Independent read-only review of the exact diff.
7. Real GUI on port 9001 with PostgreSQL, Redis, and the analysis worker; upload a non-trivial PCAP and verify distinct timestamps for durable upload, preparation, queue, worker start, and terminal persistence.

## Risks and controls

- Never call browser transfer completion “upload complete”.
- Do not use FastAPI `BackgroundTasks` or an in-memory-only preparation queue in production.
- Preparation admission and source binding must be durable before `202`.
- Claims require leases and idempotent publication to tolerate crashes and retries.
- Do not send parsed flow payloads through Redis; workers persist bounded chunks and enqueue by job ID.
- Cancellation is best-effort once work is running and must be reported truthfully.
- Existing untracked repository artifacts and caller-owned files remain untouched.
