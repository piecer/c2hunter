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
production durable queue. With `MemoryFlowStore`, it requires a dedicated,
file-backed SQLite repository on a POSIX single host. Startup takes a nonblocking
exclusive `flock` on the database inode before capture recovery or coordinator
admission; another local runtime using the same database fails startup even with
a different health-file path. The descriptor is released on startup failure or
owned coordinator shutdown. No lock file or raw-batch storage is introduced.
Do not replace the database inode while running. Noncooperating controllers,
mixed local/production deployments sharing this database, network filesystems,
and non-POSIX hosts are unsupported; this is not distributed ownership fencing.

New LIVE captures in this opt-in memory mode persist an internal source/ownership
marker plus the flow-store instance's continuity ID. Before startup can finalize
captures, marked CAPTURING/UPLOADING jobs from a different store instance become
terminal FAILED with `error_code=LIVE_CAPTURE_RESTART_INCOMPLETE` and a fixed safe
error explaining that accepted in-memory batches may have been lost. The normal
detail/list API exposes this reason; the detail UI displays an English/Korean
warning, including that zero counts do not prove absence of traffic. Sensor IDs,
existing raw/snapshot records, and capture configuration are not rewritten.
Late sensor completion heartbeats, raw batches, and due-capture processing cannot
revive a terminal job. Raw batches remain sensor-scoped and may still return 202.

Recovery does not infer loss from an empty dataset: a new empty capture and an
app recreated around the **same** memory store remain valid. Saved ANALYZING
snapshots follow the existing validated recovery path; terminal jobs are untouched.
Non-memory flow sources and the default app factory do not run this sweep.
An unmarked legacy or foreign active LIVE job makes local-memory startup fail
closed **without changing any active job**: ownership/source continuity cannot
be proven. Before upgrading/enabling this mode, finish such captures with their
original source still available, or explicitly cancel them through the existing
API. Do not invent ownership markers for old captures. This migration refusal is
deliberate; legacy captures cannot safely be automatically classified as lost.

SQLite remains authoritative only for **already saved job snapshots**, not raw
batches accepted with HTTP 202. Before restart, wait for CAPTURING/UPLOADING jobs
to save their datasets, verify saved flow counts, and use the SQLite backup API.
If an unsnapshotted capture is interrupted, start a new capture; this change makes
possible loss explicit, it does not provide raw-batch durability or replay.

Regression coverage: `controller/tests/test_local_analysis_runtime.py` exercises
LIVE ingestion to real worker result publication, SQLite startup recovery,
invalid payload refusal, detector failure, pre-start cancellation, cancellation
during execution, API responsiveness and owned-thread shutdown.
`controller/tests/test_live_restart_incomplete.py` additionally exercises actual
parser-produced flow ingestion (202), fresh SQLite connection and empty-memory
startup for both LIVE modules/states, terminal callbacks, and ownership refusal.
