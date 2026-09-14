# Network report: at-a-glance presentation

Scope: frontend presentation only; preserve the network-pattern-report-v1 and supporting measurement contracts. Independent source review passed; verification evidence is recorded separately from deployed-service acceptance.

## Acceptance

- The first view gives a qualified overall verdict, producer summary counts and up to three retained observations in producer order (all are observations, not risk scores).
- Never aggregate affected hosts across overlapping groups. Group flow/host counts are explicitly scoped; summary suspect flows and issue groups retain producer meanings.
- One supported low-confidence cause hypothesis and one localized next check; neither is a root-cause diagnosis or C2 classification.
- Coverage gaps, omissions and lower-bound counts remain visible while detailed reasons and workflow explanations start collapsed.
- All retained groups remain accessible via **전체 이상 항목 보기 / View all anomaly items**, eight per page, with one lazy evidence owner and three representative examples. Report replacement resets stale state and preserves keyboard focus.
- Supporting measurement quality remains with its evidence; saved legacy reports are never upgraded.
- AI is optional and collapsed; no automatic inference, existing consent, status, errors and cancellation preserved. Never clip a summary into a stronger claim.
- Verify real producer fixtures including controls and high cardinality, full web tests/lint/build, and offline Chromium built-App routes in Korean/English at desktop/mobile widths; record actual mounted DOM, keyboard behavior and screenshots.

## Narrow first viewport

The existing mobile navigation occupied the first 463 pixels; the verdict began at y=882.72 in a 390×844 Chromium viewport. A native menu disclosure now keeps all existing routes and sign-out available, with Enter/Space activation, Escape focus restoration, and route-selection collapse. The desktop navigation layout is unchanged. A completed network job no longer mounts an empty status panel; supplied running progress, warnings, restart-incomplete errors, cancellation controls/errors and waiting-capture status remain available. Unknown network progress is not invented.

The browser harness asserts complete verdict, first observation and priority next check rectangles inside 390×844 (and 1280×844) for supporting/mixed producer fixtures in both languages, with no horizontal overflow. Next check precedes the longer cause hypothesis; no warning or qualifier is hidden or clipped. Long job titles, analyst notes, extra job warnings and maximum omission/lower-bound reports can require scrolling: these safety messages remain visible rather than being suppressed to force a universal fold guarantee. All producer scenarios still have bounded DOM checks and representative screenshots; first-viewport fit is a measured fixture acceptance, not a claim about every arbitrary saved job.

## Evidence boundaries

The deployed service on port 18128 redirects unauthenticated inspection to `/login`; no login or bypass attempted. Offline intercepted built-App fixtures verify frontend behavior, not the user's live saved results. This work changes no backend semantics, dependencies, deployment, services or remote GitHub state. The authorized local commit contains only this plan and the web presentation, tests and browser harness. Port 18128 may still serve the previous build; local verification is not deployment verification.
