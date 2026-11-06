# Generated-data investigation evaluation

This opt-in evaluator compares **the existing** `AIAnalysisService` (legacy
selection, fixed evidence bundle, `OllamaGateway`, and its single format repair)
with `InvestigationService` (stored source, read-only evidence tools, bounded
planning, validation, and persistence). It does not change production prompts,
scores, verdicts, budgets, UI, or feature enablement.

## Commands

Run from an installed source checkout, with an isolated HOME/cache/temp directory:

```sh
python -I -B -m c2hunter_controller.ai_investigation_evaluation --help
python -I -B -m c2hunter_controller.ai_investigation_evaluation --output artifacts/evaluation-offline
python -I -B -m c2hunter_controller.ai_investigation_evaluation --output artifacts/evaluation-preflight --preflight-local-model
python -I -B -m c2hunter_controller.ai_investigation_evaluation --output artifacts/evaluation-smoke --real-local-model --case jitter_beacon
```

Every output directory must be new. The default only generates the nine-case
inventory and reports `OFFLINE_NOT_EXECUTED`, `complete=false`, and no result
rows. Preflight only performs bounded metadata GET requests. No model is pulled,
downloaded, unloaded, restarted, or automatically replaced. Real inference
requires `--real-local-model` for one pair or the separate `--real-local-matrix`
option for the fixed nine-case / eighteen-row matrix. These options and preflight
are mutually exclusive. Actual matrix execution still requires independent review
and campaign authorization; adding this path does not authorize a live run.
The report assembler requires the declared exact case × arm Cartesian product;
duplicate, missing, foreign and mismatched rows fail closed.

The approved pilot is `llama3.1:8b` at literal
`http://127.0.0.1:11434`, with default expected observed tag digest
`46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e`.
`--model` and `--expected-model-digest` must refer to an already-installed model.
Metadata is checked before and after inference. A changed or unavailable final
identity makes `comparison_valid=false` and exits nonzero, while retaining the
observed arm outcomes. Tag metadata is **not** proof of executing weight bytes.

## Generated source and production paths

Nine bounded deterministic scenarios are generated without PCAP or target
traffic: scheduled update, bulk backup, monitoring, jittered repetition,
low-volume repetition, mixed peers, SYN-only flood, partial/bad timestamp
quality, and an observed peer outside the top-one shortlist. Reserved
`192.0.2.0/24` and `203.0.113.0/24` addresses and `example.test` names are data,
never connection destinations. No payload or real user data is included.

Both arms share the same detached, generated job stored in `MemoryRepository`.
The evaluator does not fabricate scored candidates: the actual legacy prefilter
creates and ranks candidates from those stored observations. The initial stored
candidate table is empty, which is an explicit limitation of this proxy corpus.
The legacy candidate limit is one. A target outside that selection produces
`NOT_SELECTED`, not a fabricated assessment of that target or the selected
other peer. Its queued legacy run is cancelled without inference.

Scenario names and expected labels are external to the stored job and model
input. IDs and domains are neutral. The generic task is copied verbatim from
an existing legacy system-prompt sentence and used as the investigation question.
Legacy has **no** question argument: its unchanged fixed prompt already contains
that sentence. Its fixed bilingual output versus the investigation's English
request is another retained interface difference, not identical prompts.

Absent domain, TLS and flags remain absent; observed zero flags remain zero.
Malformed timestamps are not repaired: the investigation source reader's
`SOURCE_INVALID` refusal is recorded as a real failed outcome, while the legacy
path preserves its own parsing behavior. Source-job and stored-candidate hashes
are checked after each arm. Investigation evidence/facts are separate from model
interpretation. The evaluator releases its private worker slot only after the
synchronous execution returns; an unresolved stored state is reported explicitly,
not changed into an invented terminal success.

## Bounds and measurement

Common generation settings are temperature 0, context 16384, output 2048, HTTP
60 seconds and zero transport retries. These intentionally differ from legacy
production defaults (temperature .1, output 4096, one retry, 120-second HTTP
construction default). No seed or unsupported thinking option is claimed.

The legacy gateway's injectable transport is replaced **only for this experiment**
with a bounded streaming adapter: loopback-only URL allowlist, no environment
proxy, no redirects, identity encoding, 256 KiB response cap before decoding,
one HTTP attempt per invocation and a cumulative deadline. Legacy prompt,
selection, parser and one-format-repair behavior are not replaced. Its default
transport's proxy and response-buffering behavior are consequently not benchmarked.
The investigation gateway is the existing production implementation with an
observer subclass around its real admission/completion seam; its own 64 KiB
response and 16 KiB text limits remain unchanged. Different schema framing and
context admission are retained, and may yield a genuine `CONTEXT_LIMIT` outcome.

A shared budget admits at most 12 inference attempts per pair within 900 seconds.
The investigation's stricter production run/call budgets also apply. The matrix
creates a fresh experiment, trace and pair budget for each case. All pair budgets
share one 108-attempt / 8100-second admission ceiling; this clock is not restarted
between pairs. Encoding and response decoding cannot turn an expired legacy
request into an accepted success. Cancellation after admission is `CANCELLED`,
not a successful or unknown-error response.

The original execution deadline also covers final JSON serialization, Markdown
rendering, ordinary file writes/close, and the terminal receipt/return. Matrix
helper completion does not restart that clock or authorize CLI success. The shared
single-pair publisher likewise retains its original 900-second deadline. Bounded
valid and invalid diagnostic output is prepared before final publication checks.
Late finalization returns exit 2 and leaves the aggregate JSON, Markdown and final
matrix manifest marked comparison-invalid. All observed rows, per-pair reports,
admission and progress receipts remain intact; `complete=true` still means all
declared observations exist. One diagnostic rewrite may run in supervised cleanup,
but cannot re-enable success. The terminal receipt identifies the report, not a
successful comparison: consumers must check exit status and `comparison_valid`.

These in-process deadlines are cooperative, not hard CPU/process isolation.
Supervisors must separately bound lock wait (600 seconds), execution (900 seconds
for a live pair or 8100 for a live matrix), and owned-process cleanup (30 seconds).
The offline repair supervisor instead caps each verification child at 300 seconds.
All cooperating verification uses the approved persistent coordinator at
`~/.local/share/c2hunter-verification/coordination/heavy-verification.lock` with
recorded device/inode identity. Missing or replaced identity is a stop condition,
never permission to recreate the lock. This does not isolate unrelated host work.
Do not rerun failures to obtain a preferred answer. No unapproved warmup is sent.
Legacy runs first: pre-run loaded-model metadata and the order are reported, but
cold-start and order bias are not statistically controlled. Local cancellation
or process expiry does **not** prove backend generation physically stopped.

Reports include available input/output tokens, entered HTTP attempts, completed
responses, repair-prompt observations, tool steps (including the automatic seed tool, not only model-requested queries),
latencies, source/data/config
hashes and model metadata. Usage unavailable through a production error seam is
null. Monetary and physical compute costs are unobserved, never guessed as zero.
Raw provider envelopes, authorization headers, credentials and hidden reasoning
are not saved. Invalid output triage retains schema/reference checks, stable
errors, byte counts and hashes rather than raw provider text.

## Interpretation and artifacts

- `report.json`: bounded structured outcomes and metrics.
- `report.md`: readable Korean/English facts and limitations.
- `generated-cases.json`: deterministic data plus separately held proxy labels.
- `source-manifest.json`: actual installed package source/config hashes and modes.
- `admission.json`: single-pair pre-inference intent; not proof of completion.
- `observed-rows.json`: single-pair observations saved before optional post-metadata.
- Matrix mode: `matrix-admission.json`, append-only `progress-NN.json`, and
  `matrix-manifest.json` record the fixed corpus, admitted attempts and each case's
  `OBSERVED`, `UNRESOLVED` or `NOT_RUN` state. Each case has a new subdirectory with
  admission, observed rows and a report. Per-pair reports are written exclusively,
  never overwritten; the manifest binds each by its canonical JSON SHA-256.
  Only the final aggregate/report and matrix manifest may be rewritten as invalid
  diagnostics when their publication crosses the original execution deadline.

Matrix invocation (only after approval):

```sh
python -I -B -m c2hunter_controller.ai_investigation_evaluation --output artifacts/evaluation-matrix --real-local-matrix
```

A pair is persisted before the next case starts. Identity drift, unavailable or
malformed metadata, expired admission, or an execution exception stops new cases,
retains prior observations, and returns exit 2. Unrun cases are not fabricated rows
or benign results. Ordinary service-level failure/partial/omission outcomes remain
rows and do not trigger retries. A complete report means eighteen observed outcomes,
not eighteen successful model assessments. A source-invalid case retains null stored
source identity and the actual `SOURCE_INVALID` outcome; null is not a hash.

Aggregation binds producer-observed gateway model/settings, runtime package
versions and source hashes, each generated data hash, and matching stored-source
identities within each pair. Caller `comparison_valid=true` cannot substitute for
missing model observations. Observation timestamps, case IDs and loaded-model state
are retained locally but excluded from the common execution fingerprint. Tag
drift invalidates comparison even if inference completed. Per-case call telemetry
and output audits use detached trace slices; reuse cannot change prior rows.
Malformed metadata produces a static error, not raw provider content. Optional tag
size/timestamp values are bounded strict scalars; missing values remain null.

Selection coverage and positive-label omissions are separate from model accuracy.
Failures, partial facts-only results and explicit abstentions are not benign
predictions. Binary proxy accuracy uses only completed decisive positive/negative
assessments with positive/negative proxy labels; its denominator is explicit and
zero denominators produce null. False positives/negatives have the same limited
synthetic interpretation. NEEDS_REVIEW and INCONCLUSIVE abstain.

Evidence-ID existence, typed metric reference membership, and returned typed-fact
value equality are mechanical checks. They do **not** establish that free prose
is semantically supported. This is a single-run synthetic proxy, **not real-traffic
accuracy**, malware ground truth, a superiority test, or a best-model claim.

The persistent test module replaces only provider transport for real gateway and
service wiring tests. It must never reach the installed model during ordinary
pytest execution. Focused tests/static checks precede any real smoke pair; full
canonical gates and a real nine-by-two matrix belong to the review/integration
stage, not this initial evaluator execution.
