# Filtered PCAP export specification and implementation plan

Status: Implemented and verified after independent backend, frontend, and packet-format review

Verification:

- `make test`: Python 507 passed/1 skipped, sensor worker 12 passed, Web 80 passed
- Web coverage: 84.78% overall; `App.tsx` 95.79%
- `make lint`: passed in a clean clone (Ruff, formatter, mypy, ESLint, security rules, gosec)
- `make build`: passed in a clean clone through Python, Go, Web, sensor tarball, and Docker image builds

## 1. Original problem and implemented resolution

Before this change, `POST /api/v1/pcap-exports` rebuilt a packet capture only from retained upload bytes. It reparsed `get_job_capture(job_id)`, filtered decoded packet records, and always wrote a classic PCAP; it did not filter the original file byte-for-byte in place.

The implementation now resolves immutable retained sources across upload, completed LIVE, and reanalysis provenance; applies the analysis flow filters to decoded packets; and writes valid PCAP or PCAPNG while preserving interface, link type, captured/wire lengths, timestamps, and source order. Legacy raw-packet records remain a compatibility fallback only when no canonical capture exists.

## 2. Goals

1. Export packets from the retained source belonging to one analysis.
2. Preserve current candidate export and scalar filter compatibility.
3. Add `Download filtered capture` to analysis detail using the currently applied include/exclude filter groups.
4. Share nested filter normalization and predicate implementation with flow review while documenting packet-versus-aggregated-flow semantics.
5. Preserve packet link type and original/captured length and produce a capture readable by standard tools.
6. Bound synchronous source parsing and output construction.
7. Return stable, actionable failure metadata instead of silently producing a non-downloadable capture.

## 3. Non-goals and deferred lifecycle work

- Arbitrary BPF execution on the controller.
- Persisted UI filter presets.
- Packet-to-aggregated-flow session reconstruction. Export predicates operate on decoded packets.
- A durable asynchronous export queue, cross-process concurrency coordinator, export request deduplication, and export TTL cleanup. The existing synchronous repository contract is retained in this change; source/output limits and the existing API rate limiter bound each request. These lifecycle items remain follow-up work before substantially increasing capture limits.
- Deleting independently retained sensor-PCAP archives when an analysis is deleted. Existing sensor-PCAP retention ownership is unchanged.

## 4. Source matrix and immutable selection

Source selection is based on provenance, not only blob existence:

1. `PCAP_UPLOAD`: use the analysis's canonical `job_capture` only.
2. `LIVE` / sensor capture:
   - export is allowed only when status is `COMPLETED`;
   - use all sensor-PCAP segments whose `analysis_job_id` equals the source analysis ID;
   - order metadata by `(uploaded_at, id)`;
   - completed analyses reject additional sensor-PCAP uploads, preventing source-set mutation after completion.
3. `REANALYSIS`: follow `parent_job_id` until the retained canonical upload or sensor-capture source is found. Cycles or missing provenance fail safely.
4. Legacy jobs with no retained capture may use existing `flow_records` only when at least one record contains `raw_packet_hex`, preserving compatibility.
5. If canonical `job_capture` exists, associated sensor segments and inline raw records are not also read, preventing duplicate source inclusion.

At export start, the selected metadata is copied as the request's source manifest. Every sensor blob is loaded by exact ID and its bytes are checked against metadata `sha256`. Canonical upload bytes require and are checked against `job.source.sha256`. A missing digest or blob, digest mismatch, storage failure, or one corrupt segment aborts the whole request; partial exports are never persisted as completed.

Export metadata records `source_job_id`, `source_capture_count`, and a manifest of source IDs/SHA-256 values for audit reproducibility.

## 5. Resource limits

- `pcap_export_scan_max_bytes` and `pcap_export_scan_max_packets` are cumulative source-prefix limits across every selected capture. They inherit upload limits when omitted.
- A scan ceiling stops before the next source or complete packet and saves a parseable prefix artifact with `truncated=true` and `SOURCE_BYTE_LIMIT` or `SOURCE_PACKET_LIMIT`.
- `pcap_export_max_bytes` stops before the next complete PCAP packet or PCAPNG block and records `OUTPUT_BYTE_LIMIT` rather than returning a size-related 413.
- If no match exists in an incomplete scanned prefix, the export fails as `PCAP_SOURCE_SCAN_INCOMPLETE`, not definitive `PCAP_NO_MATCH`.
- Integrity/parser failures do not save a completed export blob. `pcap_export_max_concurrent` bounds overlapping synchronous work and returns `429 PCAP_EXPORT_BUSY` when saturated.
- The implementation avoids packet hex round trips, but repositories currently save `bytes`, so bounded in-memory source and output construction remains part of the synchronous contract.

## 6. API request

Extend `POST /api/v1/pcap-exports` without removing existing fields:

```json
{
  "job_id": "analysis-id",
  "candidate_id": "optional-candidate-id",
  "internal_host_ip": "optional-exact-ip",
  "start_time": "optional-RFC3339",
  "end_time": "optional-RFC3339",
  "port": 443,
  "protocol": "TCP",
  "direction": "OUTBOUND",
  "sensor_id": "sensor-a",
  "include_filters": [
    {
      "candidate_ip": "203.0.113.0/24",
      "protocol": "TCP",
      "port": 443,
      "source_port": 51000,
      "destination_port": 443,
      "direction": "OUTBOUND",
      "has_payload": true
    }
  ],
  "exclude_filters": []
}
```

Compatibility and matching rules:

- Existing scalar fields are AND conditions.
- Existing scalar `port` keeps its current meaning: match either source or destination port.
- `candidate_id` resolves to the candidate external IP and is an AND condition.
- Empty nested include list means all packets passing scalar conditions.
- Include groups are OR, exclude groups are OR, and active fields inside one group are AND.
- Nested `candidate_ip` accepts exact endpoint IP or CIDR and matches either endpoint.
- Nested `port` keeps flow-review meaning: inferred external service port. Nested `source_port` and `destination_port` match exact transport fields.
- Nested `has_payload: true` means the individual decoded packet has application payload. It does not retain payload-free SYN/ACK/FIN packets from an aggregated flow that had payload elsewhere. UI copy must state this packet-level behavior.
- UI serialization removes empty groups and omits `has_payload` when its checkbox is false, exactly as the flow query does.
- Scalar conditions run first; nested include/exclude groups run on their result.
- At most 20 include and 20 exclude groups are accepted. Unknown keys, empty groups, invalid CIDRs/directions, protocols over 32 characters, non-boolean `has_payload`, and ports outside 0..65535 return HTTP 422.
- Audit normalization canonicalizes CIDR, uppercases direction/protocol, converts timestamps to UTC, and omits inactive empty values.

## 7. Response, failures, and download format

A successfully created export keeps the current shape and adds source/format metadata:

```json
{
  "id": "export-id",
  "job_id": "analysis-id",
  "source_job_id": "canonical-source-analysis-id",
  "candidate_id": null,
  "status": "COMPLETED",
  "matched_packet_count": 12,
  "size_bytes": 1234,
  "capture_format": "PCAP",
  "filename": "c2hunter-analysis-id-filtered-export-id.pcap",
  "filter": {},
  "source_capture_count": 2,
  "source_manifest": [],
  "created_at": "...",
  "error_code": null,
  "error": null
}
```

Compatibility failures that represent a valid request with no downloadable result are persisted with `status: FAILED`:

- `PCAP_SOURCE_UNAVAILABLE`: no retained source exists for the resolved provenance.
- `PCAP_NO_MATCH`: source exists but no decoded packet matches.

A failed export download remains HTTP 409 `PCAP_NOT_AVAILABLE`. Invalid input, active LIVE analysis, source corruption/integrity errors, and resource-limit errors are request errors and do not persist a partial export.

Output rules:

- Parser records retain raw packet bytes, DLT/link type, captured length, original wire length, source order, and packet index when packet retention is requested.
- If all selected packets have one link type, output is classic little-endian microsecond PCAP with that exact DLT, a snaplen at least as large as the maximum captured packet, and preserved `incl_len`/`orig_len`.
- If selected packets contain multiple link types, output is PCAPNG with one interface description per DLT and enhanced packet blocks mapped to the correct interface.
- Timestamp output uses microsecond resolution; finer source precision is rounded to the parser's retained `datetime` precision. Packet order remains the immutable source order `(source_order, packet_index)` even when capture timestamps are non-monotonic. Timestamps outside classic PCAP range, including negative timestamps, select PCAPNG.
- Duplicate packets are not deduplicated.
- Server `Content-Type` and `Content-Disposition` use metadata format/filename. `.pcap` uses `application/vnd.tcpdump.pcap`; `.pcapng` uses `application/x-pcapng`.
- `api.download` continues honoring the server filename, so the server is authoritative for the requested filtered filename.

## 8. UI behavior

`All analysis flows` gains a `Download filtered capture` action.

- It posts `{job_id, include_filters, exclude_filters}` generated from the last applied `filters`, never unapplied `draft` edits.
- The button is outside the filter form or has `type="button"`; clicking it cannot submit/apply draft edits.
- When draft differs from applied filters, nearby copy states that download uses the last applied packet filters. Dirty state remains after download.
- The button is disabled throughout create and blob download and exposes an accessible pending label.
- On `COMPLETED`, it calls authenticated `api.download` and displays `Filtered capture downloaded (N packets)` with `role="status"`.
- On `FAILED`, it displays the server error with `role="alert"` and does not request `/download`.
- New export, apply/reset, and job change clear stale export notice/error.
- `JobFlowReviewPanel` is keyed by `jobId` (or explicitly resets all local state) so job A filters cannot leak into job B.
- Add-group controls stop at 20 groups and explain the limit.
- Copy explicitly says payload-only export includes payload-bearing packets, not every control packet from a matching aggregate flow.

Candidate detail keeps `Export candidate PCAP`; source resolution adds LIVE/parent support automatically.

## 9. Security and integrity

- Existing auth/RBAC middleware applies to create/download.
- No request field is executed as BPF, shell, SQL, or object-store path.
- Only canonical provenance or segments explicitly associated with the resolved source analysis are read.
- Source digest verification and all-or-nothing behavior prevent silent partial evidence.
- Packet bytes remain in repository binary objects and never enter public analysis responses.
- Empty/non-matching output is not advertised as a completed header-only capture.

## 10. Implemented acceptance coverage

Backend/parser/writer:

1. PCAP upload exports from retained source even when stored flow records have no `raw_packet_hex`.
2. Completed LIVE analysis with two associated sensor segments exports both and excludes an unrelated segment.
3. Active LIVE export returns 409; completed analysis rejects a late sensor segment upload.
4. Candidate export from LIVE source filters by candidate IP.
5. Reanalysis resolves its parent source; cyclic/missing provenance fails safely; legacy raw-record fallback remains.
6. Nested include/exclude behavior covers CIDR, direction, protocol, service/source/destination ports, and packet payload-only; scalar `port` any-side behavior remains unchanged.
7. Invalid/empty/21st nested group returns 422.
8. Missing source persists `FAILED/PCAP_SOURCE_UNAVAILABLE`; no match persists `FAILED/PCAP_NO_MATCH`; both downloads return 409.
9. Sensor metadata/blob missing, SHA mismatch, corrupt final segment, and parser failure produce no partial completed export.
10. Two one-packet segments with global limit one produce a deterministic one-packet partial prefix; source/output byte limits are enforced at complete packet/block boundaries.
11. Ethernet, RAW, and SLL single-link exports round-trip through `parse_pcap` with correct DLT, endpoints, packet count, raw bytes, captured/original lengths.
12. Mixed-link sources produce valid PCAPNG rather than Ethernet-mislabeled PCAP.
13. Truncated packet lengths, snaplen over 65535 where supported, duplicate packets, equal timestamps, source tie ordering, and canonical-source precedence are deterministic.

Web unit/integration:

1. Applied include/exclude groups are posted exactly; empty groups are removed.
2. Dirty draft is not posted, does not trigger a flow refetch, and remains dirty after export.
3. Completed create performs authenticated download, uses server filename, and shows packet count.
4. `FAILED` create shows error and never downloads.
5. Create HTTP/network failure and completed-then-download failure re-enable retry and clear stale success.
6. Rapid duplicate clicks issue one create/download while pending.
7. Job A to job B resets filters/page/export state.
8. Group controls enforce the 20-group boundary.
9. Existing candidate export regression remains passing.

Browser E2E follow-up:

- Executable Vitest coverage verifies candidate and filtered capture create/download behavior, filenames, errors, retry, dirty state, duplicate clicks, job reset, and group limits.
- A future Playwright fixture should exercise browser download events against synchronous `COMPLETED` responses. This is browser-level defense in depth, not a dependency of the implemented API contract.

## 11. Completed implementation tasks

1. [x] Add packet metadata retention and classic PCAP/PCAPNG round-trip writer tests.
2. [x] Add bounded nested filter fields and shared packet-filter predicate tests.
3. [x] Implement provenance resolution, terminal/source-integrity checks, cumulative limits, and stable failure metadata.
4. [x] Add backend coverage for upload, LIVE, candidate, reanalysis, mixed link types, and error paths.
5. [x] Add UI coverage and implement applied-filter download UX, pending/error state, limits, and job reset.
6. [x] Correct architecture, data-model, operations, README, and external API documentation.
7. [x] Complete independent backend, packet-format, and frontend review and resolve reproduced findings.
8. [x] Run canonical `make test`, `make lint`, and `make build` without changing unrelated user-owned files.

## 12. Definition of done

- Every implemented backend/parser/writer and Web acceptance test passes; browser-level Playwright download coverage remains the explicit defense-in-depth follow-up in section 10.
- Generated PCAP/PCAPNG is reparsed in tests; magic-only checks are insufficient.
- Existing candidate export, upload analysis, sensor PCAP, flow review, and authenticated download regressions pass.
- New backend error branches and UI success/failure/dirty-state branches have executable coverage.
- Canonical test, lint, and build pass without modifying, deleting, staging, or committing unrelated untracked files.

## 13. Final independent-review resolution and verification

The final three-way backend, packet-format, and frontend review findings were reproduced against the working tree and resolved:

- LIVE segment admission is rechecked atomically inside Memory, SQLite, and PostgreSQL repository save transactions. PostgreSQL locks the job row before object upload; terminal jobs return `JOB_CLOSED` without changing the blob store.
- Source metadata size is admitted before blob loading, export POST is rate-limited, active LIVE jobs return 409, sensor digests are mandatory, and object-store outages no longer fall back as if the canonical capture were absent.
- PCAPNG interface identity and snaplen are retained. Same-link interfaces remain distinct, original source packet order is preserved, invalid captured/original/snaplen relationships are rejected, and timestamps outside classic PCAP range use PCAPNG (including negative timestamps via interface offset).
- Non-IP-only LIVE segments no longer abort a multi-segment export, while their packets still count toward source limits.
- Legacy reanalysis fallback reads raw packets from the resolved source job.
- The UI enforces 20 include and 20 exclude groups, clears stale export status on Apply/Reset, and uses a job-specific React key without sibling collisions.

Final verification on 2026-08-21:

- `make test`: controller/analysis 507 passed, 1 storage integration skipped; sensor worker 12 passed; Web 80 passed; Web overall coverage 84.78%, `App.tsx` 95.79%.
- Clean-clone `make lint`: Ruff check/format, mypy (44 source files), ESLint, Python security checks, Go vet, and gosec all passed.
- Clean-clone `make build`: Python compile, Go build, Web production build, sensor tarball, and controller/worker/web Docker image builds all passed.
- `git diff --check` passed. User-owned conflict backup files and `c2hunter-sensor/` were not modified or removed.
