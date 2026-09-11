# Single-process local analysis worker (POC only)

`create_app(..., local_analysis_worker_health_path=Path(...))` explicitly enables
an owned local worker for a controller using `MemoryControllerQueue`. The default
app factory and Redis worker deployment are unchanged. The worker package must be
importable (from a checkout use
`PYTHONPATH=controller/src:analysis/src:sensor/worker/src`). Non-memory queues are
rejected for this option; no Redis instance is discovered or contacted.

The normal LIVE capture coordinator creates and saves the immutable job dataset,
then uses the existing enqueue path. A single worker runs the actual
`c2hunter_worker.runtime.Worker` and `execute_analysis` off the HTTP event loop.
Bounded one-entry transfer/result queues allow one computation in flight. The
existing controller memory waiting list is **not** a durable or independently
admission-bounded queue. The coordinator publishes through the existing result
handler; it never marks a job completed without the worker result. Worker errors
become FAILED, and terminal cancellation/completion remains authoritative when a
late result arrives. Cancellation does not forcibly interrupt a running detector.

Only the coordinator accesses the repository; the worker sees copied payloads and
never a SQLite connection. On startup, ANALYZING job IDs are recovered from the
repository, one payload at a time. Dataset presence, flow/packet counts and flow
schema are validated before re-enqueueing via the existing internal enqueue path.
No dataset is reconstructed from the volatile flow store. Invalid saved payloads
fail through normal error-result publication. Terminal jobs are not re-enqueued.
Publication errors are logged and the pending result is retained for retry.

Shutdown stops admission to the worker and waits up to two seconds for the owned
worker thread after stopping the coordinator. A detector still computing then has
no repository access; its unpublished ANALYZING job is recovered at next startup.
The worker's JSON health file includes status, PID, updated time, processed count
and last worker error. Coordinator failures are logged and exposed at
`app.state.local_analysis_runtime.last_error`.

## Operational limits and restart procedure

This mode is for one local controller process, not multiple Uvicorn workers or a
production durable queue. SQLite is authoritative for **already saved job
snapshots**, not for pending raw batches in `MemoryFlowStore`. Before restart,
wait for all CAPTURING/UPLOADING jobs to save their datasets; verify saved flow
counts and create a SQLite backup using the backup API. Do not restart while an
unsnapshotted capture requires volatile flows. Capture/sensor configuration is not
changed by this option.

Regression coverage: `controller/tests/test_local_analysis_runtime.py` exercises
LIVE ingestion to real worker result publication, SQLite startup recovery,
invalid payload refusal, detector failure, pre-start cancellation, cancellation
during execution, API responsiveness and owned-thread shutdown.
