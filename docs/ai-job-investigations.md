# Experimental JOB investigations

`AI_JOB_INVESTIGATION_ENABLED` defaults to `false`. New admission additionally requires
`AI_ANALYSIS_ENABLED`, an application-owned accepting investigation supervisor
(`AI_INVESTIGATION_INLINE_ENABLED`, or the existing local-worker option), and a supported
configured provider. The same supervisor owns at most two physical IP/JOB executors.
This slice advertises JOB dispatch for Memory/SQLite and explicitly initialized
PostgreSQL with the memory queue and an actually owned accepting inline runtime.
Distributed JOB negotiation and mixed-old-fleet aggregate capacity are unsupported.
The explicit migration entrypoint initializes both IP and JOB profiles; HTTP readers
and admission never initialize PostgreSQL tables. Offline SQL doubles are not live-PG
acceptance evidence.

All routes require a real ANALYST-or-higher principal, including when general API auth
is disabled. The authenticated subject determines the immutable owner; admin does not
bypass another owner's run boundary.

- `GET /api/v1/ai-job-investigations/capabilities`
- `POST /api/v1/analysis-jobs/{job_id}/ai-job-investigations`
- `GET` that collection (`limit=1`, optional `after` run digest)
- `GET` collection `/{run_id}`
- `GET` collection `/{run_id}/steps` (`limit<=10`, optional sequence `after`)
- `GET` collection `/{run_id}/evidence/{evidence_id}`
- `POST` collection `/{run_id}/cancel`

Admission uses `job-investigation-v1`, `mode: JOB`, `experimental: true`, question,
language (`ko`/`en`), idempotency_key, required nullable expected_source_sha256,
allow_remote and `baseline_mode: off`. Null pins the current source once; it remains
null in the saved request. Exact replay and history resolve saved bytes before current
source/provider/feature availability. There is no source-preview endpoint. Creation
returns 202, identical replay 200; disabled/unsupported dispatch returns 503 without
queueing. Remote providers require both server permission and per-request consent;
the application factory does not grant remote permission.

The model selects 1–3 IDs from one finite observed-peer pool, not legacy top-five
candidates. Selection commits before automatic overview seeds. Additional retrieval
uses only five existing read-only tools and selected peer IDs. All peers share limits:
6 model calls, 12 tools (including selection/seeds/invalid attempts), 4 planning
responses, one repair, 12 transport attempts, and the original 300-second execution
deadline. Source bytes are a reserved reader upper bound, not a measured transfer.
Preparation is at most 128 KiB, retained evidence 128 KiB, combined 256 KiB, each
evidence 32 KiB, final 16 KiB, run 64 KiB, request 16 KiB, response 256 KiB, steps 24.

`AUTOMATIC_SEED` is distinct from `MODEL_REQUEST`. An investigated peer has a validated
MODEL_ASSISTED assessment; seed retrieval and FACTS_ONLY fallback do not count.
Positive/benign hypotheses require peer-local support and usable counterevidence;
control-only peers cannot receive a positive C2 verdict. Missing peers remain
not assessed. COMPLETED never establishes capture completeness, trustworthy lineage,
benign omitted peers or a whole-job conclusion. History comparison is unsupported.
Cancellation and terminal publication do not free physical worker custody. The owner
joins first; ambiguous writes/retirement quarantine rather than retry inference.

Backend tests use actual Memory/SQLite, in-process ASGI, and the bounded production
gateway over `httpx.MockTransport`: no listening provider, network or real model.
`tests.test_ai_job_investigation_fixtures.producer_fixtures()` returns deterministic
producer bytes and JSON schemas. Fixture files add one newline outside the wire-byte
budget (wire limit + 1 for a saved fixture). Numeric JSON integer-value spellings are
normalized only by JOB adapters; raw observations and old IP parsers stay strict.
Saved result reads revalidate typed facts and evidence quality against the same
immutable preparation and issued peer-local evidence. This does not validate the
truth of free prose. Null measurements remain null. Run-level reason may remain null
when only the result records a reason, preserving the existing producer convention;
a non-null run reason cannot contradict its result.

A valid model-text response can still overflow the final envelope. After the single
repair opportunity, FINAL_LIMIT reduces complete model assessments to facts-only
units, then omits complete units only if necessary, with recomputed not-investigated
coverage. Issued evidence is not deleted or truncated and remains available through
steps and evidence routes. At most three replacements and three omissions are tried.

## Stored completion is not execution acknowledgement / 저장 완료와 실행 ACK의 구분

Selection and publication retain their original pre-COMMIT encoding/write/deadline
fences. The explicitly approved late-COMMIT contract is an ACK/quarantine boundary,
**not a repair of the former no-late-durable-COMPLETED guarantee**. Native COMMIT can
finish after the original deadline, or commit and then raise. A separate SQLite reader
may observe `COMPLETED` plus `HELD`. The execution outcome is then
`STORAGE_OUTCOME_UNKNOWN`, `acknowledge_exit=false`; the supervisor quarantines the
worker, stops accepting work, does not call `worker_exited`, and does not retry
inference or release the held capacity. A later rollback does not erase a committed row.
On-time completion still acknowledges and releases only after physical join.
The frozen original failing assertion/RED is retained as historical evidence; the
ordinary regression now asserts the actual row and complete approved outcome matrix.

Quarantine belongs to the current repository/runtime: its reads and admission refuse
with an unknown storage outcome. Explicitly reopening SQLite creates a new handle;
stored reads and exact-request replay can then return the saved `COMPLETED` result,
without inference, while the durable slot remains `HELD`. This is not automatic
recovery authorization, a timely-commit certificate, or an execution ACK. Operators
must reconcile uncertain ownership explicitly; this feature adds no reset, automatic
retry, committed-row deletion, or quarantine recovery protocol.

한국어: `COMPLETED`는 저장된 결과 상태입니다. 원래 기한 내 COMMIT 완료나 실행 ACK를
증명하지 않으며, 저장소를 명시적으로 다시 열어 읽은 경우에도 같습니다. 늦거나 불확실한
COMMIT은 성공 ACK 없이 격리하고 `HELD` 용량을 유지합니다. 자동 재추론·롤백 추정·슬롯
반납으로 바꾸지 않습니다. 이 변경은 사용자가 승인한 보장 경계 변경이지, 이전의 더 강한
영속 행 보장을 수리했다는 뜻이 아닙니다.

## Web authentication and historical recovery

The actual analysis route exposes saved JOB investigations independently of mutable
source lookup. A failed/missing source stays visibly failed and disables **new**
admission; saved history/evidence and an exact previously submitted retry remain
separate owner-authorized operations. Opening the entry never POSTs automatically.

One bounded tab-local pending receipt retains exact request bytes, consent, null intent
and key. A domain-separated SHA-256 credential fingerprint binds it to the authentication
session without persisting the raw credential. A different session cannot display,
retransmit, resolve or overwrite it. Returning with the **same credential**, including
reload, can recover it. A rotated credential is deliberately not inferred to be the same
principal; use owner-authorized history/operator reconciliation rather than silent
rebinding. Legacy unbound or unreadable receipts block new admission and stay intact.
There is no receipt eviction or automatic credential migration.

Login/logout and cross-tab authentication changes retire current UI/request generations
and clear principal-specific query caches, without cancelling accepted server work.
JOB and shared HTTP clients invalidate on 401 only for their captured current authority
and non-aborted request, before parsing even a malformed error body. Late retired or
foreign-authority responses cannot log out the current session.


These tests are functionality evidence, not model effectiveness or deployed acceptance.
Web parity, independent review, canonical full gates and deployed/LIVE acceptance are
separate gates; the feature remains opt-in.
