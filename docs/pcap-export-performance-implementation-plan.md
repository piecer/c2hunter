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
