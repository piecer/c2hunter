# PCAP export performance implementation plan

## Frozen scope and invariants

This document freezes the PCAP export performance work into **exactly twelve ordered stages**. A stage may start only after the preceding stage is merged and its measurements are archived. Stage 1 records the materialized Classic PCAP path; it does not claim that the path is streaming.

Every stage preserves the existing REST request/response, error, integrity, truncation, ordering, timestamp, PCAP/PCAPNG, and authorization behavior unless that stage explicitly adds an asynchronous API contract. Identifiers, addresses, filter values, filenames, and digests must never become metric labels.

The fixed production duration label set is:

```text
source_read, hash, frame, decode, filter, write, save, total
```

The fixed volume label sets are `packets={scanned,matched,exported,omitted}` and `bytes={source,output}`. These bounded enums are the only labels on the export-specific metrics.

## Reproducible Stage 1 baseline

Run the bounded deterministic workload with:

```bash
make benchmark-pcap-export
```

This writes `artifacts/pcap-export-baseline.json` and a generated PCAP artifact. The JSON records the implementation name, seed, packet count, deterministic source/output SHA-256 values, workload fingerprint, ordered stage durations, stage packet/byte/RSS snapshots, aggregate packet/byte counters, and process peak RSS. The default 10,000-packet workload is representative but bounded; tests use 32–64 packets.

Compare a future implementation against an archived report only when workload fingerprints match:

```bash
PYTHONPATH=controller/src:analysis/src .venv/bin/python tools/benchmark/pcap_export.py \
  --packets 10000 --seed 20260720 --output artifacts/current \
  --compare artifacts/pcap-export-baseline.json
```

Durations and RSS are measurements, not deterministic values. Capture bytes, hashes, counts, stage names, seed, and fingerprint are the reproducibility contract. Run performance comparisons on the same host class, Python build, dependency lock, and otherwise idle system; use several runs and report the median.

## Exact twelve-stage sequence

| Stage | Change boundary | Required verification | Commit contract |
|---:|---|---|---|
| 1 | Baseline benchmark + metrics. | Genuine RED for absent metrics and absent harness; focused GREEN; controller+analysis Python suite; harness unit tests; Ruff and mypy; archive a bounded smoke report. | One commit: `perf(pcap): add export baseline metrics`; no export algorithm change. |
| 2 | `get_job_summary` lazy loading + direct candidate + job-scoped segment query. | REDs proving summaries do not load captures, direct candidate lookup preserves authorization/not-found behavior, and segment reads are job-scoped; focused API/repository GREEN; full Python suite and Stage 1 comparison. | One query-shaping commit; no repository streaming, decoder, filter, writer, storage, or API-lifecycle changes. |
| 3 | Repository streaming source API. | Streaming contract tests for Memory, SQLite, and MinIO/Postgres adapters; chunk-boundary, digest/error, and byte-for-byte API parity tests; Stage 1 comparison. | One repository-source commit; retain the materialized fallback and do not edit decoder/filter/writer behavior. |
| 4 | Export-only lightweight decoder. | Classic PCAP and PCAPNG format, endian, timestamp, link-type, malformed/truncated input, packet-prefix, and raw-byte parity REDs; bounded-memory comparison. | One export-decoder commit isolated from the analysis ingestion decoder; retain the measured legacy export fallback. |
| 5 | Decode-time one-pass filtering. | Include/exclude, candidate, nested-filter, ordering, scan/output-limit, and scanned/matched/exported/omitted counter parity REDs; identical capture hashes where byte parity applies. | One decode/filter-pipeline commit; no writer, storage, or lifecycle edits. |
| 6 | Spooled boundary-aware writer. | Header/record/block/padding and output-limit boundary REDs for PCAP and PCAPNG; reparsing, short-write/full-disk, permissions, cleanup, digest, disk, and RSS tests. | One writer/spool commit; synchronous persistence and download behavior remain unchanged. |
| 7 | Streaming artifact save/download. | Storage-adapter save and download streaming contracts, interrupted transfer cleanup, digest/size read-back, authorization/range/error parity, and bounded controller-memory tests. | One artifact-streaming commit; no async admission or lifecycle changes. |
| 8 | Small-sync/large-durable-async hybrid. | Threshold-boundary, durable state-transition, admission, idempotency, restart, cancellation, retry, sync compatibility, and download-contract REDs; load comparison against Stage 1. | One hybrid-lifecycle commit; threshold is configurable and rollback-safe, with no packet index. |
| 9 | Offline upload structural packet-offset index. | Offline PCAP/PCAPNG offset/length/interface/timestamp structure tests; source digest binding, malformed input, stale/corrupt index rejection, rebuild, and unindexed fallback parity. | One offline-structural-index commit; index records structure only and export reads remain on the fallback path. |
| 10 | LIVE segment background structural indexing. | Segment finalization/race, restart/resume, idempotency, partial/corrupt segment, digest binding, backlog, cancellation, and fallback tests without capture-path latency regression. | One LIVE-background-indexing commit; no posting index or index-driven export reads. |
| 11 | Candidate/filter posting index. | Posting construction/update tests plus candidate/include/exclude intersection, ordering, duplicates, empty-result, stale/corrupt posting, authorization, and full-scan parity REDs. | One posting-index commit; postings narrow packet candidates but do not yet enable range-read coalescing. |
| 12 | Safe index-driven coalesced range reads. | Selected-offset parity, safe gap/size coalescing boundaries, source/index binding, stale/corrupt/missing-index fallback, short/ranged-read errors, canary metrics, final benchmark, and rollback drill. | One range-read-and-rollout commit; retain a measured fallback until a later separately approved removal plan. |

The sequence is immutable for this initiative. Reordering, combining stages, changing metric labels, or removing the fallback requires updating this plan in a dedicated review commit before implementation.

### Stage 9 implementation closeout boundary

The implemented Stage 9 boundary is an offline, canonical-`PCAP_UPLOAD`-only structural index. It is derived and best-effort: upload success does not depend on index success, and an idempotent upload replay does not rebuild. Each generation is bound to the authoritative durable capture-source-version row (source/job ID, exact object key, immutable backend version ID, verified byte size/SHA-256), capture format, index schema version, and parser contract version. The builder reads and verifies the full retained source before an atomic metadata-owner publication makes the whole interface/packet generation visible; source deletion owns removal of READY and staging generations.

There is no public REST/OpenAPI schema for the index. Stage 10 adds controller-side optional per-segment LIVE metadata: upload marks and best-effort admits eligible finalized retained segments, while a dedicated PostgreSQL/MinIO worker owns bounded reconciliation, leases, heartbeat, retry, staging/terminal cleanup, and source-bound deletion. Internal intent states are `PENDING/DEFERRED/COMPLETED/FAILED`; terminal states are never re-admitted. Upload object I/O is lock-free and uses immutable generation keys so loser compensation and old cleanup intents cannot delete a later same-named segment. A builder deadline violation fatal-stops the worker process because Python cannot safely kill the orphan builder thread; restart and lease recovery are required before new claims. Request handling never scans or waits. Both synchronous and asynchronous exports intentionally perform zero index lookups and remain on the existing fallback until Stage 12. Stage 10 adds no Stage 11 posting index, selected-offset reads, range coalescing, or other Stage 12 behavior. The PostgreSQL+MinIO path remains an explicit environment-gated integration test and a default skip is not live-backend verification.

### Stage 11 implementation closeout and Stage 12 handoff

The implemented Stage 11 boundary is an internal, derived packet-posting generation for canonical `PCAP_UPLOAD` sources and eligible finalized retained `LIVE_SEGMENT` sources that already have a READY Stage 9/10 structural parent. Its exact physical dimensions are `ALL_PACKET`, `SUPPORTED`, `SRC_ADDRESS`, `DST_ADDRESS`, `SRC_PORT`, `DST_PORT`, `PROTOCOL`, and `HAS_PAYLOAD`. Values map only to monotonically ordered packet ordinals. The posting generation contains no byte offsets or ranges, packet content, timestamps, direction, service, sensor, or interface dimension; structural offsets remain owned by the parent index.

Posting selection implements conservative filter algebra. Scalar candidate/internal-host, port, and protocol constraints intersect; conditions within an include group intersect and include groups union; an exclude group subtracts only when every active atom is represented exactly. Generic endpoint/port terms use the safe union of source and destination dimensions. Direction and other non-indexed/context-derived atoms never narrow the posting set, while a sensor mismatch may prove an empty per-source result. A stale/corrupt/missing generation, ownership race, malformed manifest, unsupported index contract, or build/query resource-limit exhaustion returns `None` and requires sequential fallback. The internal Analysis/Candidate logical views preserve immutable source-manifest order and return only a bounded safe superset of `(source order, source identity, parent structural build, packet ordinal)` references; every consumer must still apply the compiled packet predicate.

Each generation is immutably bound to the authoritative source version (kind/ID, backend version, exact size/SHA-256), capture format, READY structural parent build and digest, structural/posting schema and parser contracts, filter contract, and a digest covering the complete generation. Atomic owner publication exposes only a complete READY generation. Source deletion removes its posting lifecycle and generations, while structural-owner replacement removes the old child posting before the replacement can become authoritative. Memory, SQLite, and PostgreSQL adapters implement the same internal lifecycle. The bounded worker and opt-in bounded backfill build postings outside request handling.

Stage 11 does **not** improve export speed yet. Its Analysis/Candidate facade is deliberately absent from REST/OpenAPI and is not imported or called by sync export, durable async export, writer, artifact, or download paths; those paths perform zero posting lookups. Stage 12 alone may translate the selected ordinals through structural packet locators into source-bound, coalesced range reads, with parity/fallback/canary/rollback verification. No selected-offset read, range coalescing, or index-driven export is claimed here. The environment-gated PostgreSQL+MinIO integration path was not run during this closeout, so live-backend verification remains outstanding.

## Per-stage verification gate

For every stage:

1. Add one focused behavior test and run it to a genuine expected RED before production code.
2. Implement the smallest vertical slice and capture focused GREEN.
3. Run all existing PCAP export helper/API tests and the benchmark harness tests.
4. Run the complete controller and analysis Python suites using the repository virtualenv and the worktree `PYTHONPATH`.
5. Run `ruff check`, `ruff format --check`, `mypy controller/src analysis/src`, and `git diff --check` after the final edit.
6. Generate a bounded report, compare only compatible fingerprints, and explain duration/RSS variance rather than treating one run as a regression verdict.
7. Review `git diff` and `git status --short`; commit only that stage's intended files with the table's commit boundary.
8. Record command output, test counts, benchmark parameters, host characteristics, report path/hash, API compatibility, and remaining risks in the stage review.

A passing benchmark never replaces correctness tests, and a faster incompatible workload is not a valid comparison.
