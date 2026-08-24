# PCAP Export Source-Byte Limit Hardening Plan

Status: implementation, independent final review, and isolated canonical repository gates GREEN

## Problem

Filtered export currently rejects a retained capture or sensor segment whenever its full declared size exceeds the remaining source scan-byte budget. This scans zero packets even when a valid complete packet/block prefix fits, violating the documented prefix-limit contract for both analysis filters and candidate exports.

## Contract

- Source byte limits are cumulative across immutable sources and inclusive at complete classic-PCAP packet and PCAPNG block boundaries.
- Never split a packet record or PCAPNG block; strict/default parsing still rejects malformed or truncated captures.
- Verify full source size, digest, and metadata integrity before parsing any bounded prefix.
- Analysis include/exclude filters and `candidate_id` share one export backend path.
- Report accurate source bytes/captures/packets, matched/exported/omitted counts, `SOURCE_BYTE_LIMIT`, and stable status/error codes.
- A match in the bounded prefix may produce a completed partial artifact. No match in an incomplete prefix is `PCAP_SOURCE_SCAN_INCOMPLETE`; a budget too small for the first packet is `PCAP_SOURCE_SCAN_LIMIT_TOO_SMALL`, never `PCAP_NO_MATCH`.
- Upload admission limits and source-integrity checks remain unchanged.

## TDD tasks

1. [x] RED: add parser tests for classic PCAP exact/one-byte-below packet boundaries and strict truncated-input rejection.
2. [x] GREEN: implement minimal opt-in source-byte-bounded classic parsing and accounting.
3. [x] RED: add equivalent PCAPNG complete-block-prefix and strict truncated-input tests.
4. [x] GREEN: implement minimal PCAPNG block-boundary handling.
5. [x] RED: add canonical upload API regressions for filtered analysis and candidate exports with a source larger than the scan cap, plus candidate-after-prefix incomplete failure.
6. [x] GREEN: route both modes through cumulative byte-bounded source parsing while preserving full integrity validation.
7. [x] RED/GREEN: cover an oversized first LIVE segment with a fitting packet prefix.
8. [x] Update materially inaccurate documentation and record exact RED/GREEN evidence.
9. [x] Run focused tests, full controller and analysis suites, Ruff format/check on changed Python files, and `git diff --check`.
10. [x] Run canonical repository `make test`/`make lint`/build gates after the final documentation edit.
11. [x] Complete independent final review.
12. [x] RED/GREEN: reject malformed tails when fully scanned, but ignore classic-PCAP and PCAPNG malformed next records/blocks wholly outside an exact byte cap.
13. [x] RED/GREEN: once the packet cap is reached, stop classic PCAP before reading a malformed next record and stop PCAPNG before validating a malformed next packet block, while retaining and validating intervening non-packet blocks.

## Acceptance criteria

- Exact complete packet/block boundaries are included; one byte below excludes the unit.
- Strict parsing behavior is unchanged for malformed/truncated input.
- Canonical analysis-filter and candidate exports complete from matching bounded prefixes.
- A candidate only after the bounded prefix fails with `PCAP_SOURCE_SCAN_INCOMPLETE`.
- Too-small first-packet budgets produce `PCAP_SOURCE_SCAN_LIMIT_TOO_SMALL`.
- Cumulative counters and omission/truncation metadata are verified by executable tests.
- Full source size/digest checks occur before bounded content is trusted.
- A valid packet-limited prefix is returned even when the next packet record/block is malformed; strict parsing and packet limits that include that malformed packet still reject it.
- PCAPNG packet limits continue through complete non-packet metadata blocks and include them in the returned prefix.

## Risks

- PCAPNG non-packet blocks and interface declarations must remain structurally complete and available to decoded packet blocks.
- Byte accounting must distinguish bytes safely parsed from full source size and remain cumulative across sources.
- An incomplete prefix cannot prove a definitive no-match or complete matched-packet count.
- Strict upload parsing must not silently adopt export-only truncation semantics.

## Verification status

Python implementation is GREEN. Evidence from the isolated worktree:

- RED: `PYTHONPATH=/tmp/c2hunter-pcap-hardening-x2k9z3/controller/src:/tmp/c2hunter-pcap-hardening-x2k9z3/analysis/src /home/piecer/dev/src/c2hunter/.venv/bin/python -m pytest analysis/tests/test_pcap_ingestion.py::test_classic_pcap_source_byte_limit_includes_only_complete_packet_records -q` -> `1 failed`; `TypeError: PcapBytePrefix.__init__() missing 1 required positional argument: 'packet_limited'`.
- First GREEN of the same exact command -> `1 passed in 0.02s`.
- Parser byte-prefix focus -> `7 passed, 14 deselected in 0.02s`.
- Relevant controller export focus (analysis/candidate/incomplete/LIVE/too-small/output/packet/integrity cases) -> `10 passed, 13 deselected in 0.83s`.
- Complete parser file -> `21 passed in 0.02s`.
- Complete controller export/API file -> `23 passed in 2.09s` (97 existing deprecation warnings).
- Full Python suites: `python -m pytest controller/tests analysis/tests -q` -> `548 passed, 1 skipped, 602 warnings in 28.57s`; the storage integration test remains opt-in via `C2HUNTER_RUN_STORAGE_INTEGRATION=1`.
- Final Ruff format check -> `4 files already formatted`; Ruff check -> `All checks passed!`; `git diff --check` -> clean.
- Byte-cap malformed-tail RED: focused parameterized classic-PCAP/PCAPNG regression command -> `4 failed in 0.07s`, each with the expected `PcapParseError` from validating the next malformed header/data/block beyond the exact cap.
- Byte-cap malformed-tail first GREEN: the identical focused command -> `4 passed in 0.02s`; each case also verifies that a limit above the full malformed source still raises `PcapParseError`.
- Post-fix parser file -> `25 passed in 0.02s`; controller PCAP API file -> `23 passed, 97 warnings in 2.21s`.
- Post-fix full Python suites -> `552 passed, 1 skipped, 602 warnings in 29.67s`; the storage integration test remains opt-in via `C2HUNTER_RUN_STORAGE_INTEGRATION=1`.
- Post-fix Ruff format -> `4 files left unchanged`; Ruff check -> `All checks passed!`.
- Packet-cap malformed-next-packet RED: `PYTHONPATH=/tmp/c2hunter-pcap-hardening-x2k9z3/analysis/src /home/piecer/dev/src/c2hunter/.venv/bin/python -m pytest analysis/tests/test_pcap_ingestion.py::test_packet_limit_stops_before_malformed_next_packet analysis/tests/test_pcap_ingestion.py::test_pcapng_packet_limit_keeps_valid_non_packet_blocks_before_malformed_packet -q` -> `3 failed in 0.07s`; classic PCAP raised `classic PCAP packet data is truncated or oversized`, and both PCAPNG cases raised `PCAPNG block length is invalid` before reporting the reached packet limit.
- Packet-cap malformed-next-packet first GREEN: the identical focused command -> `3 passed in 0.02s`.
- Pre-final focused regression checks after that fix: complete parser file -> `28 passed in 0.02s`; controller PCAP API file -> `23 passed, 97 warnings in 2.04s`.
- Independent final approval passed after direct byte-cap and packet-cap boundary probes, focused parser/API/helper suites, Ruff, and diff checks.
- Canonical isolated-snapshot gates after the final implementation edit: `make test` passed (controller/analysis `555 passed, 1 skipped`; worker `12 passed`; web `82 passed`; Go and tool tests passed), and `make lint` passed (Ruff, mypy, ESLint, Go vet, and gosec).
- The isolated-snapshot build passed for Python compile, Go, web production assets, sensor tarball, and Controller/Web/Worker images. It used `GOFLAGS=-buildvcs=false` because an unrelated malformed `/tmp/.git` directory prevented Go VCS stamping, and an explicit Compose env-file path because credentials/configuration were intentionally not copied into the worktree.
- The dirty main checkout's recursive `make build` is not an authoritative product gate: pre-existing untracked `app_BACKUP_*.py` files contain conflict markers and are collected by `compileall`. Those unrelated files were preserved; the exact intended implementation snapshot passed the complete build above.
- User-visible safeguards are covered on both export surfaces: completed partial exports show limit reasons and omitted counts, failed candidate prefixes show an accessible alert, and a filtered export too small for its first packet shows the backend error plus `SOURCE_BYTE_LIMIT` without attempting download.
