# Minimal change-based CI selection

The initial policy is deliberately a **manual CSS dependency allowlist**, not a
complete repository dependency graph or an individual-test selector.

## Eligible changes

A nonempty endpoint diff may select `frontend-only` when it changes only these
existing regular CSS files:

- `web/src/styles.css` — imported by `App.tsx`.
- `web/src/investigation.css` — imported by `AIInvestigationPanel.tsx`.
- `web/src/jobInvestigation.css` — imported by `JobInvestigationPanel.tsx`.

The combined added-plus-deleted line count must be at most 200. Each old and new
file must be at most 128 KiB, UTF-8 text without NUL bytes, with Git mode 100644.
Adds, deletes, renames, mode changes, binary data and similarly named files are
not eligible. All other paths—including TS/TSX, shared fixtures, documentation,
backend code, dependency files, configuration and CI itself—select `full`.

The retained checks are `lint`, `security`, `unit-web`, `e2e` and `build`.
Their commands and setup are unchanged. In particular, Web tests may still run
Python fixture producers, and the full build still includes backend builds.
The Python/Controller shard groups, other backend unit/coverage groups and
scenario generation are deliberate job-level skips, not passed backend tests.

## Event and failure handling

PR selection compares the event head with the merge-base of the event base and
head. Fast selection also requires both event commits to be ancestors of the
actual tested checkout, whose tree must equal the event-head tree. This can
conservatively select full validation when the base branch advances.

Push selection compares the complete `before` to `after` endpoint delta, not
just the final commit. It does not claim to inspect every intermediate commit.
New branches, unavailable or invalid diff endpoints, empty diffs, unsupported
events, tags and manual `workflow_dispatch` runs use full validation. Invalid
checkout identity or policy binding is a hard failure, not permission to skip.

## Final gate and evidence

`change-plan` publishes an attempt-specific plan, its mode and SHA-256. The plan
binds the repository, run, attempt, event/ref, raw and resolved Git endpoints,
tested source and the selector/workflow policy. The final `ci` job recomputes
that plan from its own checkout before accepting the exact job-result set.
Selected jobs must succeed; only explicitly unselected jobs may be skipped.
A failed selector, missing artifact, stale attempt, wrong output, cancelled job
or unplanned skip fails the gate. No previous-run coverage is substituted.

A frontend-only verdict is **partial validation**: it does not certify omitted
backend tests, backend coverage or the health of the base revision. Full mode
retains all existing tests, shard reconciliation and package coverage floors.

Artifacts never fall back across attempts. Use **Re-run all jobs**, rather than
a failed-jobs-only rerun that lacks a plan for the new attempt. A manual workflow
run is also an explicit full-validation path. No new recurring workflow is
introduced by this initial policy.

Changes to the selector or workflow itself always select full validation.
Local real-Git CSS fixtures exercise the fast path, but are not a claim that a
hosted frontend-only run has occurred. Broader UI/document selection, automatic
dependency discovery and per-test selection are outside this initial scope.
