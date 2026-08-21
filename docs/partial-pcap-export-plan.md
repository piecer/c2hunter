# Partial PCAP Export Implementation Plan

> **For Hermes:** Implement task-by-task with strict RED-GREEN-REFACTOR and independent review before completion.

**Goal:** Return a valid packet-boundary-truncated PCAP/PCAPNG up to configured export capacity instead of discarding the whole export when source scan or output limits are reached.

**Architecture:** Keep upload admission limits unchanged. Add explicit export output and source-scan settings that inherit upload limits when unset. Resolve and verify immutable capture sources in order, scan only a bounded prefix, filter decoded packet records, and write only complete packet/interface blocks that fit the output budget. Persist explicit partial-result metadata and surface it in the Web UI.

**Tech Stack:** FastAPI/Pydantic, Python PCAP/PCAPNG parser and writer, repository metadata JSON, React/TypeScript, pytest/Vitest.

---

## Contract

- A completed export is always a structurally valid capture and never exceeds `pcap_export_max_bytes`.
- Limits are inclusive: an output exactly equal to the configured maximum is complete, not truncated.
- No packet header, packet payload, PCAPNG block, or interface declaration is split.
- `matched_packet_count` means all matching packets found in the bounded scan; `exported_packet_count` means packets written; `omitted_packet_count` is their difference.
- `truncated` is true when source scanning stopped at a byte/packet ceiling or matching packets were omitted due to output capacity.
- `truncation_reasons` uses stable machine values: `SOURCE_BYTE_LIMIT`, `SOURCE_PACKET_LIMIT`, `OUTPUT_BYTE_LIMIT`.
- If no complete packet can fit after the required capture headers, return a clear limit error rather than a misleading no-match result.
- Existing upload limits and rejection behavior remain unchanged.
- Existing clients remain compatible: `matched_packet_count`, status, filename, and download endpoint remain present.

## Task 1: Reproduce output-limit failure (RED)

**Files:**
- Modify: `controller/tests/test_pcap_export_helpers.py`
- Test: `controller/tests/test_pcap_export_helpers.py`

1. Add a classic PCAP test where the header and first packet fit but the second packet does not.
2. Assert a valid first-packet capture, exact exported/matched/omitted counts, and `OUTPUT_BYTE_LIMIT`.
3. Add exact-boundary and too-small-for-one-packet cases.
4. Run the focused tests and confirm they fail because partial-result behavior is absent.

## Task 2: Implement packet-boundary writer result (GREEN)

**Files:**
- Modify: `controller/src/c2hunter_controller/pcap.py`
- Test: `controller/tests/test_pcap_export_helpers.py`

1. Add a typed capture-build result carrying content, format, matched/exported/omitted counts, and truncation state.
2. Calculate each classic packet record or PCAPNG interface/packet block before appending it.
3. Stop before the first unit that would exceed the inclusive byte limit.
4. Keep the legacy tuple-returning helper for compatibility.
5. Run focused tests, then existing helper tests.

## Task 3: Cover PCAPNG and boundary safety (RED→GREEN)

**Files:**
- Modify: `controller/tests/test_pcap_export_helpers.py`
- Modify: `controller/src/c2hunter_controller/pcap.py`

1. Add mixed-interface PCAPNG truncation and round-trip parsing tests.
2. Verify every referenced interface is declared and output ordering is stable.
3. Verify output never exceeds the limit and no partial blocks are emitted.
4. Implement minimal PCAPNG prefix writing needed to pass.

## Task 4: Separate export settings (RED→GREEN)

**Files:**
- Modify: `controller/src/c2hunter_controller/config.py`
- Modify: `controller/tests/test_capture_limits.py`
- Modify: `.env.example`
- Modify: `docker-compose.yml`

1. Test defaults inherit `pcap_upload_max_bytes` and `pcap_upload_max_packets`.
2. Add independently configurable `pcap_export_max_bytes`, `pcap_export_scan_max_bytes`, and `pcap_export_scan_max_packets` with positive validation.
3. Preserve existing deployments by using upload values when export values are unset.

## Task 5: Preserve bounded source prefixes (RED→GREEN)

**Files:**
- Modify: `analysis/src/c2hunter_analysis/pcap.py`
- Modify: `analysis/tests/test_pcap_ingestion.py`
- Modify: `controller/src/c2hunter_controller/app.py`
- Modify: `controller/tests/test_analysis_history_pcap_api.py`

1. Add an opt-in parser mode that stops at the packet ceiling and reports truncation; upload parsing continues to reject.
2. Process sensor segments in immutable order and stop before source byte capacity is exceeded rather than failing the whole request.
3. Do not retain every source blob in a list; verify, parse, and release each segment sequentially.
4. Record processed source manifest and source byte/packet scan totals.
5. Return a partial completed export when at least one packet fits; retain integrity errors as hard failures.

## Task 6: Persist explicit partial metadata (RED→GREEN)

**Files:**
- Modify: `controller/src/c2hunter_controller/app.py`
- Modify: `controller/tests/test_analysis_history_pcap_api.py`

1. Assert `truncated`, `truncation_reasons`, `exported_packet_count`, `omitted_packet_count`, `scanned_source_bytes`, and `scanned_packet_count`.
2. Keep `matched_packet_count` backward compatible.
3. Ensure no-match and source-unavailable errors remain distinguishable from too-small output capacity.
4. Verify GET metadata and download return the same completed partial artifact.

## Task 7: Surface partial results in Web UI (RED→GREEN)

**Files:**
- Modify: `web/tests/App.test.tsx`
- Modify: `web/src/App.tsx`

1. Add failing tests for analysis-flow and candidate export partial responses.
2. Download completed partial artifacts normally.
3. Show an accessible warning with exported and omitted packet counts instead of claiming a complete download.
4. Preserve complete-export success messaging.

## Task 8: Update operator and API documentation

**Files:**
- Modify: `README.md`
- Modify: `SPEC.md`
- Modify: `TASKS.md`
- Modify: `docs/architecture.md`
- Modify: `docs/data-model.md`
- Modify: `docs/deployment.md`
- Modify: `docs/external-api-reference.md`
- Modify: `docs/operations.md`
- Modify: `docs/security.md`
- Modify: `docs/filtered-pcap-export-plan.md`

1. Document explicit export/scan settings and backwards-compatible defaults.
2. Document partial metadata, stable truncation reasons, and inclusive packet-boundary semantics.
3. Explain memory/throughput risks and async-queue threshold.
4. Mark task/spec acceptance status accurately.

## Task 9: Independent review and hardening

1. Run focused static checks and inspect all changed lines for secrets, path traversal, unsafe allocation, integer/boundary bugs, stale fields, and ambiguous count semantics.
2. Request independent backend/security and API/UI reviews.
3. Reproduce and fix every blocking finding with regression tests.
4. Keep unrelated user-owned untracked files untouched.

## Task 10: Canonical verification

1. Run focused Python and Web tests during each TDD cycle.
2. Run `make test`.
3. Run `make lint`.
4. Run `make build`.
5. Run `git diff --check` and inspect final status/diff.
6. Do not commit unless the user explicitly requests it.

## Risks and tradeoffs

- A synchronous export still materializes decoded records and output bytes; explicit scan/output limits bound this but do not make it suitable for arbitrarily large captures.
- Prefix truncation may omit matching packets later in source order; metadata must make this visible.
- PCAPNG interface declarations consume capacity; the writer must not emit packets referencing undeclared interfaces.
- A very small configured output limit may fit headers but no packet. This is a limit error, not a successful empty capture.
- Digest mismatch, missing immutable source, malformed capture, and provenance cycles remain hard failures; truncation must never conceal integrity failures in a source selected for scanning.

## Implementation status (2026-08-21)

- [x] Reproduced source byte, source packet, and serialized output hard-failure paths.
- [x] Added bounded parser and PCAP/PCAPNG packet-prefix writers.
- [x] Added independent output/source scan settings with upload-limit inheritance.
- [x] Added sequential retained-segment fetch, digest verification, and parsing.
- [x] Added full partial-export metadata and explicit zero-packet limit failures.
- [x] Added accessible Web notices for partial filtered and candidate downloads.
- [x] Added parser, writer, API, configuration, round-trip, and Web regressions.
- [x] Updated Compose, environment example, architecture, operations, API, spec, and task docs.
- [x] Passed full `make test` (530 passed, 1 skipped; worker 12; Web 81), clean-snapshot `make lint`,
  Python compile, Go build, Web production build, sensor tarball, Docker image build, compose config,
  and `git diff --check`.
