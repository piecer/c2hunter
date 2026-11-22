# Standalone candidate navigation contract

This contract applies only to `/candidates/:id`. It does not change global candidate queues, job previews, job-flow filters, or their page sizes.

## URL presentation intent

- `detail` is a closed semantic code: `evidence`, `buckets`, `network`, `ai`, `validation`, `flows`, `operations`, or `raw`.
- `evidence` is a canonical zero-based index in this candidate's retained evidence, and is only valid with `detail=evidence`.
- `flow` is the literal retained flow ID, URL-encoded by URLSearchParams. It is only valid with `detail=flows`. No flow record is manufactured from an ID: selection must match a real record and job on the requested source page.
- `flow_page` and `bucket_page` are canonical positive, one-based integers. Traffic bucket pages are checked against the retained bucket count. Flow pages are read individually at the unchanged 50-row API limit; there is no search across other pages for an ID.
- Duplicate owned keys, malformed integers, missing/out-of-range evidence indices, incompatible combinations, and unknown section codes do not open a detail and are not automatically repaired. Unrelated query keys and the fragment remain list/navigation context.
- Explicit changes push history; selecting the same item is a no-op, including a deep link with a different query-key order. Closing/Escape replaces the current entry after deleting only `detail`, `evidence`, and `flow`. It preserves both page conditions and all other context, never navigating back to an external referrer.
- The canonical route without query parameters remains an overview. URL intent can initiate bounded reads only, never a POST, analysis execution, export, or analyst label.

## Ownership and restoration

The result surface and nested mutation owners remain mounted across query changes. Closing synchronously retires presentation before the scheduled router transition commits, so Escape does not leave the shell inert while the URL is already closed. Eight retained flow-owner admissions, pinning, draft/error retention, pending-operation settlement, authoritative-source checks, and layout lifetime fences are unchanged. FlowReviewRow business mutation code and the native delete confirmation are unchanged.

Each history entry binds to the evidence/source that admitted it. Definitive 403/404/410 retirement, actual evidence replacement, source-scope replacement, and authentication-epoch transitions require a fresh explicit selection. A later fresh selection does not reactivate retired history entries or captured action tokens. Metadata-only refetches retain structural evidence identity; transient 503 failures retain valid selections and pending work. A refreshed flow response for a different page revokes action admission even if it contains the same flow ID.

Navigation history has one FIFO capacity of **50 total entries per QueryClient/authentication scope**, shared by all candidates, including abandoned forward branches and overview entries. No per-candidate history maps or unbounded tombstone sets exist. Source-query changes are observed even off-route; definitive retirement and source/evidence replacement remain retired across source-analysis navigation, cached A→B→A and Back. This is frontend selection authority, not evidence of a server authorization bypass or an automatic write.

Each entry contains primitive source/flow identifiers, retirement flags and small focus/scroll descriptors, never an HTMLElement, detached subtree, evidence object or authority callback. The evidence-identity index has at most one weak slot per live entry (therefore at most 50); it cannot retain evidence and is pruned synchronously when entries retire or expire. Retirement drops the source descriptors and snapshot; eviction drops the record entirely. Query-cache evidence and the eight pinned mutation owners/drafts/pending outcomes remain separate and are not evicted by this presentation budget. Lookup and revocation scan at most the bounded registry, never an accumulated route history.

Browser state carries only a random entry identity and a noncredential authentication epoch, not business/evidence/secret data. A marked entry missing from the registry is expired, including after registry recreation or document reload: Back cannot silently turn it into a new admission. An unmarked genuine deep link and an explicit fresh selection still work; neither revives an older retired/expired entry. Closing still replaces the URL without returning to an external referrer.

Back/Forward within retained entries restore selection, source/bucket page and available focus/scroll descriptors. Focus descriptors retain only tag and an exact label/text of at most 256 characters, not input values or report text; an unavailable target falls back to the navigation control. A user interaction while the initial candidate read is delayed defers automatic presentation. **Open requested detail** explicitly resumes the complete validated read-only intent, preserving literal flow ID, requested page, unrelated query context and fragment. It does not normalize invalid intent or search other flow pages; missing or mismatched requested-page membership remains a refusal. No detail autofocus, flow read or write occurs before that explicit resume.

## Initial presentation and complete data access

- The overview retains status, counts, at most three primary reasons, all retained coverage warnings, and the next-check instruction.
- Three immediate evidence buttons plus a native selector expose every retained evidence item; seven section entries remain ordinary controls. This replaces the previous thirty-button evidence stack without cropping evidence data.
- The full candidate identifier is behind **Candidate identifier**, a keyboard-accessible native disclosure. Its complete, exact value is materialized only while open, including loading/error diagnostics when no source record is available. It is neither shortened nor replaced by an ellipsis. Raw candidate JSON remains exact and explicitly reachable.
- The brief chart remains available. Initial navigation precedes the chart so the first detail entry is within the 900px first fold for the full-metadata 1280px/390px fixtures, including the long IPv6 address, over-500-character identifier, TI limitations, historical notes, thirty evidence items and six hundred buckets.
- Existing lazy metric disclosures, four compact metric summaries, 20-value metric pagination, 50-bucket pagination, raw nested values and all hundred scalar values remain accessible. Closed disclosures do not keep their expanded data descendants mounted.
- Candidate labels retain the existing Korean/English presentation; this route has no report-language switch. No new UI framework or locale behavior is introduced.

## Verification scope

Persistent actual-App tests are in `web/tests/CandidateDetailNavigation.test.tsx`. Chromium coverage is in `web/e2e/candidate-detail-navigation.spec.ts`, alongside the unchanged candidate-result-selection, A-closure and workflow browser suites. Browser fixtures exercise complete evidence traversal, exact raw JSON/identifier access, initial/expanded DOM ceilings, no horizontal body overflow, actual Back/Forward/Escape, original-opener focus, delayed reads, requested flow pages and a pending label's exact payload. These are isolated fixture results, not observations of a deployed service. Integration and independent acceptance remain separate parent-owned gates.

The history regressions measure actual application map sizes and strong references, not only connected DOM: exact capacity/+1, abandoned branches, cross-candidate visits, repeated source replacement, off-route ABA, registry recreation and eight pinned pending owners through history eviction. Weak-index removal is checked synchronously without requesting or awaiting garbage collection. Deferred-flow browser cases run at 1280px and 390px with valid, missing, wrong-page and wrong-job responses plus evidence-resume positive controls. The canonical final unit gate is coverage-bearing `npm --prefix web run test`; focused `test:unit` receipts alone do not replace it.
