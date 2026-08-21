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

Filtered PCAP export is synchronous and uses the same configured byte and packet ceilings. It validates cumulative source metadata before loading blobs, verifies every retained source digest, and constructs bounded output in Controller memory. Keep limits below available Controller memory and object-store throughput; do not substantially increase them without introducing a durable asynchronous export queue. Active LIVE jobs cannot be exported, and completed/terminal jobs reject late sensor-PCAP segments so a recorded source manifest remains immutable.

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
