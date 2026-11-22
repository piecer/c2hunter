# Interpretation cancellation ownership (R1)

Cancellation is an explicit operator action, not automatic cleanup. The stable
job/authentication owner retains accepted work when its report/source view retires.
Leaving that job or authentication epoch retires its callbacks and actions.

Each module retains at most **four** cancellation receipts. Each receipt contains
only run identity metadata, requested language, acknowledgement state, and a
read-reconciliation state. It does not retain the report, output, or error body.
The receipt object is the attempt identity; callbacks must still own that exact
object in the current job/auth owner. An older run's pending transport, failure,
reconciliation, or dismissal never resets another run's cancellation state.

A validated newer B can be cancelled while A's POST or explicit GET is pending,
or A's GET is unavailable. Repeated clicks for the same unresolved attempt are
synchronously deduplicated. Responses must match the captured run/module/job,
dataset where present, and requested language. A source-retired callback retains
its own acknowledgement/uncertainty but cannot invalidate source/status queries.

Unconfirmed receipts offer an explicit matching status GET. A terminal GET does
not manufacture the original POST acknowledgement or physical worker release.
Successfully acknowledged or read-reconciled receipts can be explicitly dismissed;
pending/unconfirmed receipts cannot. At four retained receipts a different run's
cancel action is refused with a resource-capacity explanation, not a fabricated
cancellation failure. Nothing is silently evicted. Reconciliation alone does not
free capacity; dismissal is a separate operator action.

The same identified receipts and controls appear in Network and DDoS status,
the source-error stable owner, and the narrow DDoS detail status portal. The
current run's controls use only its own receipt plus the explicit capacity guard.
Admission, source/citation ownership, discovery, polling, and retry-consent guards
remain independent and unchanged.

## Regression provenance

`InterpretationCancellationIsolation.test.tsx` drives actual App UI and HTTP
scheduling. Its first two tests were observed RED with B disabled after A's late
ACK, before implementation. The capacity explanation was separately observed RED.
The added schedules cover B before A settles, late failure/malformed/wrong-language
ACKs, A reconciliation during B pending/failure, source-error controls, exact
POST targets, deduplication, retained receipt capacity/no eviction, and job/auth
departure. No predecessor tests or assertions were changed.

The new browser spec covers both modules at 1280/390 pixels in Korean/English,
with cancellation both before and after A's late ACK. It uses the shipped stale
reconnect path and explicit source recovery, opaque IDs, unreadable A status,
ordinary clicks and narrow-detail portal accessibility. Browser setup corrections
preserve the initial failed traces: an immediate reconnect list refresh otherwise
kept A fresh for ten seconds; the fixture now reports the concurrent list outage.
DDoS detail is opened through its real evidence disclosure, not the AI opener.
The sign-out control intentionally clears query caches; the new departure test
asserts absence rather than preservation of pre-sign-out data. These are new
fixture corrections, not changes to existing product protocols or deadlines.

This candidate is not integrated. Independent source closure and parent A/B plus
4C composition remain required. Runtime gate receipts live outside this source
snapshot; this document does not assert their results in advance.
