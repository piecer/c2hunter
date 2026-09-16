# Operations Runbook

## Routine checks

```bash
docker compose --env-file .env ps
curl -fsS http://localhost:8000/api/v1/health
curl -fsS http://localhost:8000/api/v1/ready
curl -fsS http://localhost:8000/api/v1/metrics
```

Alert on offline/degraded sensors, queue depth, spool bytes, capture drops, clock offset, job failures, object-storage growth, DB capacity, and certificate expiry. `/health` is process liveness; `/ready` must represent dependency readiness.

## Authentication and token management

### Static bearer tokens

The Controller validates `Authorization: Bearer <token>` headers by comparing
SHA-256 digests (`security.py:70-99`). To rotate a token:

1. Compute the new digest: `echo -n 'new-token' | sha256sum | cut -d' ' -f1`
2. Update the corresponding `C2HUNTER_*_TOKEN_SHA256` variable in `.env`
3. Restart the Controller container so pydantic settings reload

Existing sessions minted via dev-login are stored in-process memory
(`security.py:41-67`) and expire on restart or TTL expiry (default 900 s).
There is no cross-process revocation — if a token is compromised, rotate the
digest immediately and audit Controller logs for unauthorized requests.

### Rate limit exceeded (HTTP 429)

The Controller returns HTTP 429 with a `Retry-After` header when a fixed-window
limit is exceeded (`security.py:103-127`). The header value is the number of
seconds until the current window's oldest request expires. Typical scenarios:

- **Dev-login flood** — client IP exceeded `C2HUNTER_DEV_LOGIN_RATE_LIMIT`
  (default 10/min). Wait for `Retry-After`, then retry with exponential backoff.
- **Enrollment-claim spike** — automated tools claiming multiple enrollments.
  Review audit logs for suspicious enrollment tokens.
- **Analysis-job burst** — a user/script creating too many jobs. Check the auth
  subject in `/api/v1/metrics` counters and investigate if unexpected.

The rate limiter runs per-controller process. In multi-replica environments,
aggregate limits can be higher than configured expectations. Use ingress-level
rate limiting or Redis-backed distributed counters for strict production control.

To adjust limits at runtime without restart is not supported — change the env
variable and restart the Controller. Monitor 429 response codes in Prometheus:

```bash
curl -fsS http://localhost:8000/api/v1/metrics \
  | grep 'c2hunter_api_request_duration_seconds\|c2hunter_api_requests_total'
```

Controller AI observability is exposed in the API registry as `c2hunter_ai_enqueue_duration_seconds`, `c2hunter_ai_queue_waiting_depth`, `c2hunter_ai_enqueue_failures_total`, and `c2hunter_ai_feedback_total`. Model execution, processing depth, and validation failures are exported separately by the AI worker as described below. Alert on sustained queue growth, schema-invalid output, failures, or p95 latency regression rather than a single event.

## Disk and retention

Defaults are raw PCAP 7 days, Flow 30, results 180, audit 365, and heartbeat detail 30. Set organization policy before capture. Monitor Docker volume and sensor spool filesystems with byte and inode thresholds. PCAP is opt-in; narrow BPF and shorter capture/rotation reduce risk. Cleanup must be paged and audited. An expired PCAP changes availability; it must not delete candidate evidence.

AI Run, Assessment, generated draft, and analyst-feedback ledgers follow the parent Analysis Job result-retention period. Job deletion cascades these records in Memory, SQLite, and PostgreSQL, deleting feedback and artifacts before assessments and runs. Feedback remains append-only while the parent job exists; never delete individual feedback rows to rewrite analyst history.

Offline PCAP upload defaults to 500 MiB and 2,000,000 packets. The bundled web proxy accepts the same size, streams request bodies to the Controller, and allows up to 10 minutes for upload processing. Configure any external reverse proxy with a matching or larger request-body limit and timeout. Tune `C2HUNTER_PCAP_UPLOAD_MAX_BYTES` and `C2HUNTER_PCAP_UPLOAD_MAX_PACKETS` below available Controller/Worker memory, PostgreSQL I/O, and MinIO capacity. The original upload is retained once in MinIO, normalized flow records are stored separately from job metadata, and Redis carries only a job reference. Raw packet bytes are reconstructed from the retained object only for an explicit export. Use Analysis history for metadata correction; use reanalysis for detector changes. Only terminal jobs can be manually deleted, and manual deletion intentionally cascades to candidates, the retained source capture, and generated exports.

For `ddos_attack`, keep Controller and analysis worker on the same release before admitting jobs. The worker
returns a validated bounded report, not Candidates. Alert on `INVALID_DDOS_RESULT`, input/target/bucket/finding
limit warnings, unavailable baselines, partial sensor capture, and sustained worker queue growth. Response codes
are advisory and require operator approval; C2Hunter does not apply firewall, FlowSpec, RTBH or scrubbing changes.
See [DDoS 공격 트래픽 분석](ddos-attack-analysis.md).

Stage 9 builds a derived, best-effort structural index while accepting a canonical offline `PCAP_UPLOAD`. Stage 10 extends the same internal metadata model to eligible, finalized, retained LIVE segments. The upload request only marks and durably admits work; it never scans or waits, and queue capacity/dependency/metrics failures do not change the existing 201 response or canonical source. LIVE bytes are uploaded without a repository/DB lock to an immutable generation key (`sensor-pcaps/{sensor_id}/{segment_id}/{generation}.pcap`); duplicate-race losers compensate only their exact key, while the public filename and segment response remain unchanged. Historical deterministic keys remain valid because reads and cleanup use the metadata's exact object key. `pcap-offset-index-worker` owns separate PostgreSQL/MinIO connections, lease recovery, bounded marker reconciliation, stale staging cleanup, terminal cleanup, heartbeats, retries, and oldest-eligible claims. Source/job binding and deletion cascades prevent publication after canonical LIVE source deletion. The index remains optional controller-side per-segment metadata with no public API/OpenAPI schema. Sync and claimed durable async exports intentionally perform zero index lookups until Stage 12. Stage 10 includes no Stage 11 posting index and no Stage 12 selected-offset/range-read path.

Bound resource use with `C2HUNTER_PCAP_OFFSET_INDEX_MAX_PACKETS`, `...MAX_INTERFACES`, and `...BATCH_SIZE`. Queue/worker controls are `...LIVE_ENABLED`, `...QUEUE_CAPACITY`, `...WORKER_CONCURRENCY`, `...LEASE_SECONDS`, `...LEASE_RENEW_SECONDS`, `...MAX_ATTEMPTS`, `...RETRY_BASE_SECONDS`, and `...JOB_TIMEOUT_SECONDS`; renewal must be at most half the lease, timeout must exceed it, and concurrency cannot exceed capacity. Intent markers are `PENDING/DEFERRED/COMPLETED/FAILED`: reconciliation retries only the first two, and terminal cleanup must not recreate the latter two. A timed-out builder may remain blocked in an orphan daemon thread, so the worker enters fatal-stop, stops heartbeats and claims, leaves lease recovery to the durable ledger, and the process must be restarted; do not continue serving work or close a repository still used by that orphan. Reconciliation, staging/terminal cleanup, shutdown grace, and the dedicated low-cardinality Prometheus endpoint are bounded by the corresponding `...RECONCILE_*`, `...STAGING_*`, `...CLEANUP_*`, `...TERMINAL_*`, `...SHUTDOWN_GRACE_SECONDS`, and `...METRICS_PORT` settings. The real PostgreSQL+MinIO path remains opt-in via `C2HUNTER_RUN_STORAGE_INTEGRATION=1`; a default skip is not live-backend verification.

### Stage 11 packet-posting index operation

Stage 11 is optional internal derived metadata, not an export feature flag. `C2HUNTER_PCAP_POSTING_INDEX_ENABLED` defaults to `false` and must be set consistently for the Controller and the Compose `pcap-offset-index-worker` service. That service jointly runs Stage 10 structural workers and Stage 11 posting workers against PostgreSQL/MinIO and exposes both metric families on the existing internal `C2HUNTER_PCAP_OFFSET_INDEX_METRICS_PORT` (default `9104`); there is no separate posting port. Enabling postings admits new eligible canonical uploads/finalized LIVE segments and starts `C2HUNTER_PCAP_POSTING_INDEX_WORKER_CONCURRENCY` posting threads. It does not change REST/OpenAPI responses and does not make sync or durable async export consume postings.

Key posting queue controls are `...QUEUE_CAPACITY`, `...WORKER_CONCURRENCY`, `...LEASE_SECONDS`, `...HEARTBEAT_INTERVAL_SECONDS`, `...MAX_ATTEMPTS`, `...RETRY_BASE_SECONDS`, `...OPERATION_TIMEOUT_SECONDS`, `...POLL_INTERVAL_SECONDS`, `...RECONCILE_INTERVAL_SECONDS`, and `...RECONCILE_BATCH_SIZE`. Heartbeat must be at most half the lease, operation timeout must exceed both heartbeat and lease, and concurrency cannot exceed capacity. Recovery runs before reconciliation and claims; expired running tasks retry only within the persisted attempt bound. `...STAGING_MAX_AGE_SECONDS`/`...STAGING_CLEANUP_BATCH_SIZE` remove only unowned stale staging generations, while `...TERMINAL_RETENTION_SECONDS`/`...TERMINAL_CLEANUP_BATCH_SIZE` bound terminal task cleanup. Canonical source deletion and structural-owner replacement own child posting cleanup; do not delete posting rows manually.

Build resource ceilings are `...BUILD_MAX_PACKETS`, `...BUILD_MAX_MEMBERSHIPS`, `...BUILD_MAX_DISTINCT_KEYS`, `...BUILD_MAX_ENCODED_BYTES`, `...BUILD_MAX_CHUNKS`, and `...BUILD_BATCH_SIZE`. Internal safe-superset selection is separately fail-closed by `...QUERY_MAX_OPERATIONS`, `...QUERY_MAX_RESULT_ORDINALS`, `...QUERY_MAX_DECODED_MEMBERSHIPS`, `...QUERY_MAX_DIRECTORY_CHUNKS`, and `...QUERY_MAX_DICTIONARY_TERMS`: exceeding any query bound returns no posting view and requires sequential fallback. These settings do not authorize Stage 12 offset/range reads.

Historical backfill has a separate explicit switch and is **disabled by default**. Set both `C2HUNTER_PCAP_POSTING_INDEX_ENABLED=true` and `C2HUNTER_PCAP_POSTING_INDEX_BACKFILL_ENABLED=true`, choose a conservative `C2HUNTER_PCAP_POSTING_INDEX_BACKFILL_BATCH_SIZE`, and restart the joint index worker. Each admitted source is read completely and digest-verified, so backfill can consume substantial MinIO bandwidth, PostgreSQL write I/O, CPU, and encoded-index storage even though admission and reconciliation are batched. Start with a small batch during a maintenance window, watch backlog/build duration/storage throughput, and disable backfill after the intended population is declared; ordinary posting workers may remain enabled for new sources.

Posting metrics use only fixed bounded labels:

- `c2hunter_pcap_posting_index_admissions_total{source_kind,outcome}`: source kind `PCAP_UPLOAD|LIVE_SEGMENT|other`; outcome `queued|coalesced|deferred|ineligible|error|other`.
- `c2hunter_pcap_posting_index_tasks_total{source_kind,outcome,reason}`: outcome `completed|retry|failed|stale|other`; reason `none|build_rejected|storage|timeout|lease_lost|deleted|heartbeat_unavailable|worker_fatal|other`.
- `c2hunter_pcap_posting_index_queue_depth{status}`: `QUEUED|RUNNING|COMPLETED|FAILED|other`.
- `c2hunter_pcap_posting_index_build_seconds{source_kind,outcome}`: build outcome `completed|failed|stale|timeout|other`.
- `c2hunter_pcap_posting_index_memberships_total{source_kind}` and `c2hunter_pcap_posting_index_encoded_bytes_total{source_kind}`.

Do not add source IDs, object keys, addresses, build IDs, or digests as metric labels. `C2HUNTER_PCAP_POSTING_INDEX_METRICS_ENABLED=false` suppresses posting collectors only; it does not disable indexing.

For rollback, set `C2HUNTER_PCAP_POSTING_INDEX_ENABLED=false` in both Controller and worker environments and restart them. This stops new posting admission/claims but leaves source data, structural indexes, and existing derived posting rows intact for later lease recovery or bounded cleanup. No export rollback is required because Stage 11 export paths perform zero posting lookups. To pause only historical population, leave the main switch enabled and set `...BACKFILL_ENABLED=false`.

Troubleshooting:

- **No postings appear:** confirm the main switch in both containers, a READY source-bound structural parent, worker readiness, and that the source is canonical/retained/eligible. A full queue may leave an intent `DEFERRED`; reconciliation admits it when capacity returns.
- **Queue remains `RUNNING`:** inspect lease/heartbeat storage availability and worker logs. On restart, lease recovery requeues or terminally fails the exact attempt; never edit lease tokens or attempts by hand.
- **Timeout/fatal worker exit:** a timed-out Python builder cannot be killed safely. The shared fatal control stops both posting and structural claims in the joint process. Restore PostgreSQL/MinIO health or lower work bounds, restart the whole `pcap-offset-index-worker`, and let durable lease recovery proceed.
- **Repeated `FAILED` generation:** inspect the stable internal error and source/parent/version/digest binding. Permanent malformed, stale, corrupt, contract, or resource-limit failures are terminal; do not repeatedly re-admit them without replacing the authoritative source or structural parent through the supported lifecycle.
- **Posting view is broad or returns fallback:** non-indexed atoms deliberately leave a broad safe superset. Missing/stale/corrupt ownership, unsupported index contracts, manifest races, or query-limit exhaustion return fallback instead. Neither outcome is evidence that export range reads ran or that export became faster.

The PostgreSQL+MinIO integration test remains opt-in with `C2HUNTER_RUN_STORAGE_INTEGRATION=1` and was not run for the Stage 11 documentation closeout. Unit/adapter parity does not substitute for live-backend verification.

### Stage 12 indexed export rollout and rollback

Stage 12 remains **off by default**. Configure Controller and `pcap-export-worker` identically with these exact settings and defaults: `C2HUNTER_PCAP_INDEXED_EXPORT_MODE=off` (`off|shadow|active`), `C2HUNTER_PCAP_INDEXED_EXPORT_CANARY_BASIS_POINTS=0` (valid only in shadow), `C2HUNTER_PCAP_INDEXED_EXPORT_MAX_SOURCES=128`, `C2HUNTER_PCAP_INDEXED_EXPORT_MAX_GAP_BYTES=65536`, `C2HUNTER_PCAP_INDEXED_EXPORT_MAX_RANGE_BYTES=8388608`, `C2HUNTER_PCAP_INDEXED_EXPORT_MAX_RANGES=4096`, `C2HUNTER_PCAP_INDEXED_EXPORT_MAX_TOTAL_FETCHED_BYTES=268435456`, `C2HUNTER_PCAP_INDEXED_EXPORT_MAX_AMPLIFICATION_NUMERATOR=4`, `C2HUNTER_PCAP_INDEXED_EXPORT_MAX_AMPLIFICATION_DENOMINATOR=1`, `C2HUNTER_PCAP_INDEXED_EXPORT_MAX_SOURCE_FRACTION_NUMERATOR=1`, and `C2HUNTER_PCAP_INDEXED_EXPORT_MAX_SOURCE_FRACTION_DENOMINATOR=2`. Posting indexing must be enabled before shadow/active. Sparse active success never calls a full-source open/get and reads only exact immutable ranges; dense or unsafe plans fall back sequentially once. Shadow always treats sequential output as authoritative and never publishes the provisional indexed artifact.

Roll out after READY index coverage stabilizes: shadow 1% (`100` basis points), then 10% (`1000`), then 100% (`10000`), then active with canary reset to `0`. Hold each step long enough for representative PCAP/PCAPNG, upload/LIVE and filter mixes. Promote only when artifact SHA/size/count parity is exact, errors do not regress, typed fallback rates are understood, range bytes/source bytes improve for sparse workloads, amplification and source fraction remain within configured ceilings, and CPU/duration/spool/peak RSS remain within the deployment budget. Do not promote from a single benchmark timing. Roll back immediately by setting mode `off` in both services and rendering `docker compose --env-file .env config`; restart Controller/export workers. Off performs zero Stage 11/12 lookups and preserves sequential behavior. Existing derived indexes may remain for later use.

Metrics use bounded labels only: `c2hunter_pcap_indexed_export_executions_total{path}` (`indexed|shadow|sequential|fallback`), `c2hunter_pcap_indexed_export_fallback_total{reason}`, `c2hunter_pcap_indexed_export_shadow_parity_total{result}`, and unlabeled `c2hunter_pcap_indexed_export_requested_ranges_total`, `c2hunter_pcap_indexed_export_coalesced_ranges_total`, `c2hunter_pcap_indexed_export_selected_payload_bytes_total`, `c2hunter_pcap_indexed_export_fetched_bytes_total`, and `c2hunter_pcap_indexed_export_source_saved_bytes_total`; `c2hunter_pcap_indexed_export_amplification_total{bucket}` and `c2hunter_pcap_indexed_export_source_fraction_total{bucket}` use fixed labels. Never add source IDs, object keys, addresses, filters, job IDs or hashes.

MinIO/S3 must support standards-compliant exact byte Range GETs, immutable/versioned object identity (or generation-unique keys), exact metadata/stat, and read-after-write consistency for the retained key. Lifecycle rules must not expire canonical retained captures or LIVE segments before PostgreSQL retention/outbox cleanup, and must retain the existing incomplete-multipart abort rule for exports. Troubleshoot `index_unavailable/index_corrupt` by checking READY source→structural→posting ownership; `resource_limit` by inspecting range count, fetched bytes, amplification and source fraction; `range_missing/range_short/range_unavailable/version_drift` by checking provider range semantics, immutable version/key and lifecycle; `ownership_changed` by checking source replacement/deletion or index publication races. Do not widen bounds merely to suppress fallback. The PostgreSQL+MinIO Stage 12 gate is opt-in and was not run in this closeout.

Filtered PCAP export defaults to hybrid execution. Trusted work at or below both `C2HUNTER_PCAP_EXPORT_SYNC_MAX_SOURCE_BYTES=33554432` (32 MiB, inclusive) and `C2HUNTER_PCAP_EXPORT_SYNC_MAX_PACKETS=100000` stays on the bounded synchronous path; an exceeded or unknown estimate is admitted to the PostgreSQL-owned durable queue. `C2HUNTER_PCAP_EXPORT_EXECUTION_MODE=sync_only` stops **new** async admission only. Do not stop `pcap-export-worker`, status/cancel/download routes, or shared database/object storage while accepted async rows remain `QUEUED` or `RUNNING`.

Queue capacity counts `QUEUED + RUNNING`. Principal-scoped idempotency/coalescing lookup happens before new-job capacity checks, so a replay remains available when full; only new work receives `429 PCAP_EXPORT_QUEUE_FULL` with `Retry-After`. Claims are oldest-eligible and lease-token guarded (PostgreSQL uses `FOR UPDATE SKIP LOCKED`): default lease 120 seconds, heartbeat 30 seconds, maximum 3 claims, persisted retry delays based on 5 then 10 seconds, and cooperative timeout 1,800 seconds. Expired leases recover to retry/terminal state; stale attempts cannot update progress or publish. Cancellation is immediate for queued work and cooperative for running work.

Publication is metadata-last: verify source size/SHA, build and independently reparse a packet-boundary-complete artifact, commit an object-key-bound `UPLOADING` cleanup intent, upload to the immutable attempt-owned staging key without holding a database lock, verify remote size, and atomically stage hidden artifact metadata while changing that exact intent to `STAGED`. The lifecycle completion transaction locks every cleanup intent for the object key and publishes only when the canonical publication intent is the sole `STAGED` owner; it consumes that intent while publishing metadata and the terminal `COMPLETED` winner. A crash before that transaction leaves both hidden metadata and its durable cleanup owner. A later attempt first converts any prior unpublished object to `READY` cleanup and removes its stale metadata before uploading. Post-staging compensation locks every intent for the exact object key before winner detection, removes stale intents without deleting a published winner, otherwise reuses the publication-scoped identity, consolidates duplicates, and leaves one `READY` retry owner until object deletion succeeds. Orphan maintenance atomically claims cleanup rows as `DELETING`, excludes keys referenced by a completed lifecycle, and cannot race completion because publication requires sole cleanup ownership; an aged `UPLOADING` row remains protected while its exact attempt and lease are `RUNNING`, and a publication that loses the cleanup-state CAS fails closed rather than exposing an object selected for deletion. Cleanup IDs bind both lifecycle scope and object-key digest, and acknowledgements match both ID and object key so a retry cannot overwrite or acknowledge another attempt's object. Orphan cleanup never deletes referenced completed artifacts. Terminal retention and explicit parent-job deletion commit durable cleanup-outbox records for generated exports and the canonical job capture before removing public artifact/lifecycle metadata, acknowledge each record only after object deletion, and retry an object-store outage through orphan cleanup. Independently retained sensor-PCAP archives keep their existing retention ownership when an analysis is deleted. Terminal cleanup enforces three independent bounds: age (`C2HUNTER_PCAP_EXPORT_TERMINAL_RETENTION_SECONDS`), row count (`...TERMINAL_MAX_COUNT`), and retained artifact bytes (`...TERMINAL_MAX_ARTIFACT_BYTES`).

The dedicated export worker exposes liveness/readiness and Prometheus metrics separately on `C2HUNTER_PCAP_EXPORT_METRICS_PORT` (default 9103). Readiness fails when PostgreSQL or object storage is unavailable. Alert on queue depth by state, enqueue result, duration by mode/status, retry reasons, lease expiry, stale progress, retained artifact bytes, orphan-cleanup result, worker unready, and jobs approaching timeout. The worker never consumes Redis analysis/AI queues.

Existing scan/output safeguards remain: `C2HUNTER_PCAP_EXPORT_MAX_BYTES`, `...SCAN_MAX_BYTES`, and `...SCAN_MAX_PACKETS` inherit upload ceilings when omitted; the synchronous semaphore `...MAX_CONCURRENT` defaults to 1 and returns `429 PCAP_EXPORT_BUSY`. At scan/output ceilings, stop before the next complete source/packet/block and return a parseable partial prefix. Source blobs remain one-at-a-time size/digest-verified streams. Capacity planning must cover worker concurrency, construction/download spool disk and inodes, PostgreSQL queue rows, and object-store staging plus retained artifact bytes.

Artifact persistence/download defaults to `C2HUNTER_PCAP_ARTIFACT_IO=streaming`; `legacy` is a temporary same-layout rollback path, not a retry. Every streaming download is fully size/SHA-validated in a private local spool before response headers, including a complete bounded second read of that immutable spool. `C2HUNTER_PCAP_DOWNLOAD_SPOOL_MAX_MEMORY_BYTES` defaults to 8 MiB per concurrent download; larger artifacts roll to `C2HUNTER_PCAP_DOWNLOAD_SPOOL_DIRECTORY`, or the system temporary directory when blank/unset. Capacity planning must include concurrent spool disk bytes and inodes. Monitor this filesystem for ENOSPC/permission failures, which return sanitized `503` before headers. After successful validation, an operating-system read failure can only terminate the already-started HTTP body and clean up the spool; HTTP cannot retract headers already sent.

MinIO/S3 bucket provisioning **must** install an `AbortIncompleteMultipartUpload` lifecycle rule for the configured export bucket. SDK cleanup of a named object does not guarantee that remote multipart parts are aborted after process, network, or SDK failure. Provision with credentials authorized to manage bucket lifecycle (application credentials may remain least-privileged):

```bash
cat > /tmp/c2hunter-export-lifecycle.json <<'JSON'
{"Rules":[{"ID":"c2hunter-abort-incomplete-multipart","Status":"Enabled","Filter":{"Prefix":"exports/"},"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":1}}]}
JSON
aws --endpoint-url "$C2HUNTER_S3_ENDPOINT" s3api put-bucket-lifecycle-configuration \
  --bucket "${C2HUNTER_S3_BUCKET:-c2hunter}" \
  --lifecycle-configuration file:///tmp/c2hunter-export-lifecycle.json
aws --endpoint-url "$C2HUNTER_S3_ENDPOINT" s3api get-bucket-lifecycle-configuration \
  --bucket "${C2HUNTER_S3_BUCKET:-c2hunter}"
rm /tmp/c2hunter-export-lifecycle.json
```

Operator verification is mandatory after initial provisioning, bucket replacement, or lifecycle changes: the `get-bucket-lifecycle-configuration` output must contain the enabled rule, the `exports/` prefix, and `DaysAfterInitiation` of 1. If it is absent or altered, stop export traffic, re-run the `put-bucket-lifecycle-configuration` command with the reviewed policy, verify it, and inspect object-store capacity/incomplete multipart metrics before resuming. The Controller does not mutate or claim to verify this administrative policy at startup, preserving compatibility with external buckets and least-privileged runtime credentials.

Analyst-guided Payload signatures are also snapshotted outside compact job metadata. Signature changes
affect only analyses created afterward; use reanalysis to apply them to retained evidence. Structural
matches are monitor-only until reviewed. Disabling a bad signature preserves its versions and source
label while excluding it from future snapshots. Payload preview reparses the retained source capture
only after an explicit analyst action and returns at most 256 bytes; repeated previews of large captures
are CPU/I/O intensive and should not be used as a polling endpoint.

At 70% disk, investigate growth; at 80%, shorten optional retention or add capacity; at 90%, stop new PCAP capture before metadata/audit integrity is endangered. Never manually delete database files from a mounted volume.

## Packet drops and backpressure

Compare `captured_packets_total`, `dropped_packets_total`, pending/spool bytes, interface counters, and job sensor loss. Validate capture privileges, ring/buffer sizing, CPU affinity, storage latency, BPF selectivity, batch size, and Controller ingestion rate. Application payloads on well-known ports are retained without invoking unrelated application decoders; for example, a non-SIP payload on UDP/5060 remains analyzable. Malformed or truncated L2-L4 frames are isolated to that packet, counted as decode errors and dropped packets, and do not degrade the sensor. Source, queue, spool, or transport failures remain health errors. Backpressure order is memory queue → file spool → smaller batches → retry → explicit deletion or capture stop. Any loss must be reported, never silently discarded.

### Sensor BPF expression support

Sensor capture filters are evaluated after packet decoding in userspace. The supported primitives are
`ip`, `ip6`, `tcp`, `udp`, `icmp`, `port N`, `src port N`, and `dst port N`. Expressions support
parentheses and the boolean operators `not`, `and`, and `or`, with precedence `not` > `and` > `or`.
Adjacent primitives imply `and`. Global and per-interface BPF expressions are combined with `and`.
Malformed or unsupported expressions reject the desired capture configuration instead of silently
matching all traffic. These filters reduce retained/processed traffic but do not reduce packets entering
the AF_PACKET socket; use upstream network controls when kernel-level capture reduction is required.

## Time synchronization

Run `timedatectl status` and `chronyc tracking` (or the site's PTP tooling) on Controller and every sensor. Target ≤100 ms; >2 seconds marks a sensor DEGRADED and reduces analysis confidence. Correct NTP reachability before restarting analysis; do not hide offset warnings by editing result timestamps.

## Backup

Use application-consistent native tools and encrypt backup media:

```bash
docker compose --env-file .env exec -T postgres pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB" > c2hunter-postgres.dump
docker compose --env-file .env exec -T clickhouse clickhouse-client --query 'BACKUP DATABASE c2hunter TO Disk(backup, latest)'
```

Replicate MinIO buckets with versioning/object-lock policy where appropriate and save object inventory/checksums. Redis is not authoritative, but queue loss can interrupt work; drain or quiesce jobs before maintenance. Store configuration and CA/revocation metadata separately—never private keys in ordinary backups without dedicated key controls.

The PostgreSQL dump includes `ai_analysis_runs`, `ai_candidate_assessments`, `ai_generated_artifacts`, and `ai_feedback`; verify all four tables are present in the archive catalog before declaring an AI-capable backup complete. No model credential or raw packet/payload belongs in these tables or evaluation reports.

## Restore drill

Restore into an isolated environment using the same pinned versions. Restore PostgreSQL, ClickHouse, and MinIO, reconcile object references/checksums, start Redis, then Controller and Worker. Verify `/ready`, sensor records, one historical result, PCAP access authorization, and audit continuity. Record RPO/RTO and test quarterly. Do not overwrite production to test a restore.

For AI restore verification, select one completed Run and confirm its Assessment bundle hash, generated draft revisions, and analyst-feedback order. Run `make test-ai` and `make evaluate-ai`; compare the generated profile metrics with the pre-backup report without sending restored evidence to an external model.

## AI evaluation and model-profile operation

`make evaluate-ai` executes the fixed AI-A–AI-J Flow fixture through candidate generation, Evidence Builder, deterministic FakeGateway, strict output/evidence validation, and artifact generation. It reports Recall@20, Precision@20, malicious ranks, reduction ratio, verdict quality, Brier calibration, citation/safety metrics, stage latency, and actual bundle token estimates. `make benchmark-ai` repeats the same pipeline and records total/stage latency, CPU time, peak traced memory, candidate metrics, and token totals. Reports contain labels and aggregate metadata only, never raw PCAP, packet, or payload bytes.

The local gateway cache is bounded LRU and keyed by provider, model, non-secret endpoint/model configuration hash, prompt hash, output-schema hash, and canonical Evidence Bundle hash. Cached values are schema/evidence validated again before use, and cancellation is checked before return. Restarting the worker safely clears this optimization cache.

Controller metrics at `/api/v1/metrics` expose enqueue latency/failure, waiting depth, and analyst-feedback totals. The AI worker exposes actual Run execution latency, model/validation failures, schema-invalid totals, and waiting/processing depth on the internal `ai-worker:9102/metrics` endpoint (`C2HUNTER_AI_METRICS_PORT`). Configure Prometheus to scrape both endpoints; do not interpret Controller enqueue latency as model inference latency.

## Failure recovery

- **Controller:** queue intake pauses; restart after dependencies are ready. DB state is authoritative.
- **Redis:** restore service; idempotent tasks may redeliver. Verify no duplicate side effects.
- **Worker:** restart; late ACK and DB ledger should allow safe retry.
- **Sensor network:** local spool grows and replays after reconnect; inspect loss counters.
- **MinIO:** disable new PCAP/export, retain metadata/flows, retry bounded jobs after recovery.
- **PostgreSQL:** stop state-changing services, restore DB, reconcile ingestion ledger and ClickHouse watermark.
- **Partial sensor failure:** preserve usable data as `PARTIALLY_COMPLETED` with explicit failed sensor/loss details.

## Performance tuning

Run `make benchmark-1m`; archive `artifacts/benchmark-1m.json` and `.md` with host CPU/RAM/storage. Tune chunk and DB insert sizes without materializing the full dataset. Measure stage time and peak RSS; goal is <180 seconds and <8 GiB on the reference Controller. For Sensor 100k PPS, tune capture ring, CPU pinning, BPF, flow timeout, spool disk, and NIC offload based on measured drops. Run one change at a time and retain baseline artifacts.

### Controller/PostgreSQL latency

Job metadata, immutable normalized flow records, and per-job Payload signature snapshots are stored separately. Controller schedulers, history/detail APIs, state transitions, and terminal UI polling must not hydrate the flow/signature payload. Worker queue messages contain a job ID and the Worker loads both immutable snapshots from PostgreSQL only when analysis starts.

The first Controller start after upgrading migrates legacy `flow_records` out of `controller_objects` into `job_flow_records` and embedded `payload_signatures` into `job_payload_signatures`. This is idempotent, but a database with large historical uploads can temporarily consume substantial CPU, I/O, and free disk while the transaction runs. Back up PostgreSQL, provide disk headroom, deploy during a maintenance window, and wait for `/ready` before judging steady-state latency. After a successful migration, run ordinary online statistics maintenance:

```bash
docker compose --env-file .env exec -T postgres sh -lc \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "VACUUM (ANALYZE) controller_objects;"'
```

Do not run `VACUUM FULL` during normal service; it takes an exclusive table lock.

For a latency spike, capture a synchronized snapshot before restarting services:

```bash
date -u
docker compose --env-file .env stats --no-stream
docker compose --env-file .env ps
curl -fsS http://localhost:8000/api/v1/metrics \
  | grep -E 'c2hunter_api_request_duration_seconds|c2hunter_api_requests_total'
docker compose --env-file .env logs --since 15m --timestamps controller worker postgres \
  > c2hunter-latency.log
```

Inspect active queries, legacy payloads, and table sizes:

```bash
docker compose --env-file .env exec -T postgres sh -lc \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<'SQL'
SELECT pid, application_name, state, now() - query_start AS age,
       wait_event_type, wait_event, left(query, 240) AS query
FROM pg_stat_activity
WHERE datname = current_database() AND state <> 'idle'
ORDER BY query_start;

SELECT count(*) AS legacy_jobs_with_inline_flows
FROM controller_objects
WHERE kind = 'job' AND data ? 'flow_records';

SELECT count(*) AS legacy_jobs_with_inline_signatures
FROM controller_objects
WHERE kind = 'job' AND data ? 'payload_signatures';

SELECT count(*) AS flow_payload_jobs,
       pg_size_pretty(COALESCE(sum(pg_column_size(data)), 0)::bigint) AS payload_size
FROM job_flow_records;

SELECT count(*) AS signature_snapshot_jobs,
       pg_size_pretty(COALESCE(sum(pg_column_size(data)), 0)::bigint) AS payload_size
FROM job_payload_signatures;

SELECT relname,
       pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
       n_live_tup, n_dead_tup, last_autovacuum, last_autoanalyze
FROM pg_stat_user_tables
WHERE relname IN ('controller_objects', 'job_flow_records', 'job_payload_signatures',
                  'job_candidates', 'audit_events')
ORDER BY pg_total_relation_size(relid) DESC;
SQL
```

Both legacy counters must be zero after readiness succeeds. If latency persists, collect the command output, `c2hunter-latency.log`, request path and UTC time range, job count, largest upload size, active signature count, PostgreSQL/Controller CPU and memory limits, storage type, and whether the spike occurs during upload, analysis, flow review, history browsing, or idle time. Do not include PCAP contents, credentials, bearer tokens, or Payload previews.

## Common commands

`make up`, `make down`, `make lint`, `make test`, `make generate-test-pcaps`, and `make benchmark-1m` are safe documented entry points. `make clean` removes generated caches/results, not named service volumes.
