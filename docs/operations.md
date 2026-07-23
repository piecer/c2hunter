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

Offline PCAP upload defaults to 500 MiB and 2,000,000 packets. The bundled web proxy accepts the same size, streams request bodies to the Controller, and allows up to 10 minutes for upload processing. Configure any external reverse proxy with a matching or larger request-body limit and timeout. Tune `C2HUNTER_PCAP_UPLOAD_MAX_BYTES` and `C2HUNTER_PCAP_UPLOAD_MAX_PACKETS` below available Controller/Redis/PostgreSQL capacity, because decoded records and retained packet bytes are part of the analysis dataset. Use Analysis history for metadata correction; use reanalysis for detector changes. Only terminal jobs can be manually deleted, and manual deletion intentionally cascades to candidates and generated exports.

At 70% disk, investigate growth; at 80%, shorten optional retention or add capacity; at 90%, stop new PCAP capture before metadata/audit integrity is endangered. Never manually delete database files from a mounted volume.

## Packet drops and backpressure

Compare `captured_packets_total`, `dropped_packets_total`, pending/spool bytes, interface counters, and job sensor loss. Validate capture privileges, ring/buffer sizing, CPU affinity, storage latency, BPF selectivity, batch size, and Controller ingestion rate. Backpressure order is memory queue → file spool → smaller batches → retry → explicit deletion or capture stop. Any loss must be reported, never silently discarded.

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

## Common commands

`make up`, `make down`, `make lint`, `make test`, `make generate-test-pcaps`, and `make benchmark-1m` are safe documented entry points. `make clean` removes generated caches/results, not named service volumes.
