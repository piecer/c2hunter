# Saved IP and job investigation navigation

## Presentation and ownership

The opened investigation area starts with saved runs and the selected scoped report. New-request controls are mounted only after **New investigation request**. Saved reads do not depend on current capability, model availability, native crypto or current source availability; an actual read refusal is still shown as an error.

The admission owner is not the history-selection owner. Each session retains at most one admitted run and one cancellation owner, plus the selected history run when different. These are a fixed-size set, not a run-controller registry. Only the selected run mounts its full presentation; retained owners show small status/return controls. A completed acknowledged outcome has an explicit acknowledgment action. An unconfirmed cancellation remains retained. Navigation never POSTs cancellation or automatically retries admission.

IP admission keeps the captured body and idempotency key through endpoint selection, history paging, form closure and purpose changes. One replacement endpoint can be deferred visibly, then applied explicitly after the captured request is resolved or released. This does not submit it. Job admission retains the existing tab-local `JobIntent`, exact body/key and `expected_source_sha256=null` intent. Unreadable storage continues to block admission, not saved reads. Semantic job/authentication departure still uses the existing retirement boundaries.

### Effectful child inventory

- Session capability, preview/history and admission owners remain outside lazy forms.
- IP `InvestigationRunView` and job `RunView` retain polling/cancel owners while their presentation is hidden.
- Evidence and receipt reads are display-owned. Their old publications are retired on replacement/unmount; no write is dispatched by opening them.
- `InvestigationConclusion`, `InvestigationExecution`, `ScopeDetails`, facts, pages and coverage are presentation-only.
- `PeerDetail` owns only its scoped evidence read. It contains no approval, feedback, export or historical-reference mutation owner.
- Legacy artifact approvals, feedback, exports and historical-reference inputs live in App's separate legacy AI area, which this change does not conditionally mount or modify. Their retained-owner regressions remain required.

## Source and status recovery

The route owns the lazy IP entry even when its button first appears during a failed source read. Recovery of that source is a visibility change, not session retirement: selected history, held cancellation and its uncertainty survive. The unopened entry still performs no investigation queries or form allocation. Source errors remove stale job actions and block fresh source-dependent preview/admission; the existing captured-request recovery is separate. Job/authentication departure still retires the session.

A failed IP status read stops its polling chain with explicit uncertainty. Selecting a validated newer nonterminal history snapshot resumes that stopped chain; subsequent reads use the unchanged two-second cadence. Healthy chains are not duplicated. Older, foreign, malformed and improperly changed equal-revision snapshots cannot clear the failure or resume observation. IP snapshots compare nested semantic values rather than in-memory object identity, and reject terminal regression and decreasing progress.

## Lost cancellation acknowledgment

Both investigation types distinguish the original cancellation response from a subsequently observed terminal state. While the cancellation transport is pending, history cannot release the retained client slot. After failure or timeout, a validated terminal observation exposes **Acknowledge observed terminal outcome**, including inside a narrow evidence modal. This explicit action releases only that run's retained client slot, enabling cancellation of another run; it does not claim that the original ACK arrived, that the physical worker exited, or that capacity was returned by the server. The original-ACK-unknown qualifier is not automatically erased by history or by the acknowledgment. Retained callbacks release only their matching run, never a successor owner. Nonterminal uncertainty still offers the existing direct cancellation retry.

## Scoped summaries and citations

IP and job summaries initially show at most three representative model claims, separately from observed facts and analyst confirmation. Support, counterevidence, uncertainty, next checks, issued evidence and all retained peers remain reachable. IP claim pages contain three items; fact/evidence pages retain their bounded four-item behavior. Job peer pages remain eight items and retain all 32 producer-retained peers. Counts and omission/unknown-coverage warnings are not recomputed from the visible page. FACTS_ONLY, selected-but-unassessed and unknown whole-job coverage are not benign conclusions.

Evidence lookup uses the selected run and peer identity. A metric citation carries the complete metric reference to the renderer, while the request uses its exact evidence ID. The selected metric's evidence page opens directly. Identifiers remain complete; stored model/source prose is not translated. Display labels use `ReportLanguageContext`, while request language remains separately captured intent.

## Accessibility and responsive scope

Evidence is a named nonmodal region above 640 CSS pixels and a native modal dialog at or below 640 CSS pixels. It focuses its heading on entry. Close/Escape returns to the still-connected invoker or the same owner's heading; asynchronous read completion does not refocus the user. Arrow movement does not activate a citation. A narrow evidence dialog includes a small projection of retained admission/operation state, not another mutation controller. Explicit recovery has a close action and does not cancel server work.

The persistent browser suite exercises the actual App with producer-generated reports and controlled HTTP schedules at 1280×900 and 390×900 in Korean/English. 640×450 is an additional 200%-equivalent CSS reflow check for a 1280×900 viewport; it is not browser-chrome zoom or screen-reader certification. The complete application envelope includes long names/notes, processing/source metadata and capture warnings. Initial document budget is 1200 elements; selected-detail peak budget is 2500. Each browser case preserves overview/selected PNGs and measured counts/read/write receipts.

These are scripted-model producer and browser transport tests, not deployed service, physical capture, live-model or screen-reader acceptance. Shared language-selector convergence and parent-owned consumer-label adaptations belong to integration, not this component slice.
