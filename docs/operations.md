# Operations Runbook

## Routine checks

```bash
docker compose --env-file .env ps
curl -fsS http://localhost:8000/api/v1/health
curl -fsS http://localhost:8000/api/v1/ready
curl -fsS http://localhost:8000/api/v1/metrics
```

Alert on offline/degraded sensors, queue depth, spool bytes, capture drops, clock offset, job failures, object-storage growth, DB capacity, and certificate expiry. `/health` is process liveness; `/ready` must represent dependency readiness.

## Disk and retention

Defaults are raw PCAP 7 days, Flow 30, results 180, audit 365, and heartbeat detail 30. Set organization policy before capture. Monitor Docker volume and sensor spool filesystems with byte and inode thresholds. PCAP is opt-in; narrow BPF and shorter capture/rotation reduce risk. Cleanup must be paged and audited. An expired PCAP changes availability; it must not delete candidate evidence.

Offline PCAP upload defaults to 500 MiB and 2,000,000 packets. The bundled web proxy accepts the same size, streams request bodies to the Controller, and allows up to 10 minutes for upload processing. Configure any external reverse proxy with a matching or larger request-body limit and timeout. Tune `C2HUNTER_PCAP_UPLOAD_MAX_BYTES` and `C2HUNTER_PCAP_UPLOAD_MAX_PACKETS` below available Controller/Worker memory, PostgreSQL I/O, and MinIO capacity. The original upload is retained once in MinIO, normalized flow records are stored separately from job metadata, and Redis carries only a job reference. Raw packet bytes are reconstructed from the retained object only for an explicit export. Use Analysis history for metadata correction; use reanalysis for detector changes. Only terminal jobs can be manually deleted, and manual deletion intentionally cascades to candidates, the retained source capture, and generated exports.

At 70% disk, investigate growth; at 80%, shorten optional retention or add capacity; at 90%, stop new PCAP capture before metadata/audit integrity is endangered. Never manually delete database files from a mounted volume.

## Packet drops and backpressure

Compare `captured_packets_total`, `dropped_packets_total`, pending/spool bytes, interface counters, and job sensor loss. Validate capture privileges, ring/buffer sizing, CPU affinity, storage latency, BPF selectivity, batch size, and Controller ingestion rate. Application payloads on well-known ports are retained without invoking unrelated application decoders; for example, a non-SIP payload on UDP/5060 remains analyzable. Malformed or truncated L2-L4 frames are isolated to that packet, counted as decode errors and dropped packets, and do not degrade the sensor. Source, queue, spool, or transport failures remain health errors. Backpressure order is memory queue → file spool → smaller batches → retry → explicit deletion or capture stop. Any loss must be reported, never silently discarded.

## Time synchronization

Run `timedatectl status` and `chronyc tracking` (or the site's PTP tooling) on Controller and every sensor. Target ≤100 ms; >2 seconds marks a sensor DEGRADED and reduces analysis confidence. Correct NTP reachability before restarting analysis; do not hide offset warnings by editing result timestamps.

## Backup

Use application-consistent native tools and encrypt backup media:

```bash
docker compose --env-file .env exec -T postgres pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB" > c2hunter-postgres.dump
docker compose --env-file .env exec -T clickhouse clickhouse-client --query 'BACKUP DATABASE c2hunter TO Disk(backup, latest)'
```

Replicate MinIO buckets with versioning/object-lock policy where appropriate and save object inventory/checksums. Redis is not authoritative, but queue loss can interrupt work; drain or quiesce jobs before maintenance. Store configuration and CA/revocation metadata separately—never private keys in ordinary backups without dedicated key controls.

## Restore drill

Restore into an isolated environment using the same pinned versions. Restore PostgreSQL, ClickHouse, and MinIO, reconcile object references/checksums, start Redis, then Controller and Worker. Verify `/ready`, sensor records, one historical result, PCAP access authorization, and audit continuity. Record RPO/RTO and test quarterly. Do not overwrite production to test a restore.

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

Job metadata and immutable normalized flow records are stored separately. Controller schedulers, history/detail APIs, state transitions, and terminal UI polling must not hydrate the flow payload. Worker queue messages contain a job ID and the Worker loads the immutable payload from PostgreSQL only when analysis starts.

The first Controller start after upgrading migrates legacy `flow_records` out of `controller_objects` into `job_flow_records`. This is idempotent, but a database with large historical uploads can temporarily consume substantial CPU, I/O, and free disk while the transaction runs. Back up PostgreSQL, provide disk headroom, deploy during a maintenance window, and wait for `/ready` before judging steady-state latency. After a successful migration, run ordinary online statistics maintenance:

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

SELECT count(*) AS flow_payload_jobs,
       pg_size_pretty(COALESCE(sum(pg_column_size(data)), 0)::bigint) AS payload_size
FROM job_flow_records;

SELECT relname,
       pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
       n_live_tup, n_dead_tup, last_autovacuum, last_autoanalyze
FROM pg_stat_user_tables
WHERE relname IN ('controller_objects', 'job_flow_records', 'job_candidates', 'audit_events')
ORDER BY pg_total_relation_size(relid) DESC;
SQL
```

`legacy_jobs_with_inline_flows` must be zero after readiness succeeds. If latency persists, collect the command output, `c2hunter-latency.log`, request path and UTC time range, job count, largest upload size, PostgreSQL/Controller CPU and memory limits, storage type, and whether the spike occurs during upload, analysis, history browsing, or idle time. Do not include PCAP contents, credentials, or bearer tokens.

## Common commands

`make up`, `make down`, `make lint`, `make test`, `make generate-test-pcaps`, and `make benchmark-1m` are safe documented entry points. `make clean` removes generated caches/results, not named service volumes.
