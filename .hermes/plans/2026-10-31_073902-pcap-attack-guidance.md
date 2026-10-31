# Offline PCAP attack guidance implementation plan

Goal: Find review-worthy DoS/DDoS-shaped traffic intervals in an uploaded PCAP and explain the observed pattern, target/time/evidence, limits and passive next checks. Preserve conservative DDoS classification and never claim general intrusion/L7 coverage or confirmed malicious packets.

Baseline: master 73b13ceabf334075e57a4bfa92f77989071d9838. Read-only audit and actual probe artifacts: /home/piecer/.hermes/cache/scratch/pcap-attack-guidance-ki54zf3z/{parent,audit-detector,audit-product}. Existing source snapshot764files; no actual.env/backups/caller untracked contents accessed.

Authority: user requested review, plan and corrections. Implementation is approved; commit, push, deployment, service restarts, production DB changes, LIVE traffic and model calls are not. Older unfinished AUTO/L7 work is not an input. Use existing installed dependencies only. Keep actual9001/deployed acceptance distinct from isolated source/browser verification.

## Verified gaps

1. Whole-capture shape mixing: an isolated1200SYN interval is detected; adding600later payload-bearing ACK packets to that target produces no finding. Local interval should remain inspectable without promoting it to confirmed attack.
2. Fixed eligibility floors: short/high-rate SYN or strong relative UDP change can receive no target/type-specific guide; lower source counts get only a global warning. That warning currently disappears when a different target has a finding.
3. Offline UI emphasizes C2 and unexplained thresholds; public protected targets need explicit CIDR context. A valid pending DDoS job is incorrectly called unsupported.
4. Low-source warning incorrectly says single-source; prominent Next check selects mitigation rather than evidence investigation.

The existing positive classification/evidence/signatures, strict report validation, partial-coverage handling, normal-reference evaluation and legacy exports are useful and remain intact. Parent4PCAP upload/worker-parity controls, detector11PCAP cases+120tests, product6durable-path tests support the audit. These are synthetic characterization cases, not real-world precision/recall or attack-intent proof.

## Architecture and compatibility

Retain ddos-attack-report-v1 through v4 without adding unknown fields to them or weakening their verdict/gate validation. Add a separate closed, versioned job artifact `pcap_attack_guidance` (`pcap-attack-guidance-v1`) for offline PCAP DDoS jobs. It is candidate investigation, NOT a second attack verdict and NOT C2 findings. Historical absence is allowed and visibly means not generated; malformed-present/foreign-owner artifacts reject rather than fall back. Existing AI continues interpreting the existing DDoS findings only; UI must explicitly separate its scope from deterministic guidance candidates.

One shared job-level analysis helper must produce both artifacts in inline and worker paths. Observe normalized packet records during the existing bounded traversal, rather than rerunning an exhausted generator or inventing packet timing for aggregated flows. Metadata is persisted with the normal job result transaction. Bind guide job_id/dataset_id and counts to the actual job/report at result admission and readback. Reanalysis recomputes the artifact for its new owner; do not inherit a parent's guide or put it on a changed analysis module. Old worker/old historical absence remains unavailable, never a clean review result.

## Scope and bounded candidate policy

- Fixed five-second UTC-aligned packet windows, exact observed first/last timestamps, one strongest review window per target/port/protocol/role. Whole-input DDoS findings remain unchanged except independently preserving the existing low-source warning.
- Candidate families: SYN concentration, payload-free ACK burst, RST burst, UDP burst, ICMP burst. Existing full DDoS findings still provide their richer reflection/multi-vector assessment; no new claim of application-layer classification, exploitation, credential abuse or actor attribution.
- Minimum32eligible observed packets per candidate window. SYN concentration needs >=0.8 SYN-only share; clearly observed matching SYN-ACK response abundance must suppress or qualify benign connection controls. ACK candidates require observed payload absence and burst evidence; ordinary payload transfer stays negative. UDP/ICMP candidates need existing volume evidence or a >=5x relative increase against at least3earlier occupied eligible windows. No padding with invented idle/normal samples. Short/low-source candidates may be retained as review hypotheses, never by fabricating DDoS gate evidence.
- Candidate policy is fixed/versioned, not an instruction to lower user DDoS thresholds. Relative baseline is explicitly within this capture, not known-normal traffic. No baseline/partial capture/one-sided visibility remains unknown. A normal burst can resemble a candidate; give competing explanations and checks, not a calibrated attack probability.
- Limits:256target keys,8192total window states,512windows per target,32retained source identities per window and8displayed examples,32published candidates,128KiB canonical UTF-8 guide output. Source counts become explicit lower bounds when capped. Bound reverse-response tracking too. Candidate omission, state overflow, ineligible aggregated records and inherited parser/capture gaps must remain explicit. No resource-limit removal or broad target-tracker rewrite.
- Exact immutable fields, enum registry and JSON schema are owned by the producer slice and frozen with its generated fixtures before client integration. All numeric facts use finite safe integer-value semantics where integral (booleans/strings/fractions rejected); exact closed nested keys and timestamp containment apply. No arbitrary producer prose, payloads, secret values or callable/executable filters in the guide.

## Implementation slices

### A. Existing product-path corrections (parallel with B)
Files: web/src/App.tsx, web/src/DDoSAttackPanel.tsx, web/src/ddosReportTranslations.ts; scoped web/tests/PcapUploadOwner.test.tsx, DDoSAttack.test.tsx, DDoSStage3.test.tsx and uniquely named new tests if needed.
- RED then GREEN: explicit offline attack-triage entry selecting existing ddos_attack module (keep legacy API/default routes compatible), protected-network/CIDR help, advanced disclosure retaining actual posted numeric defaults and optional normal reference.
- Correct known-module pending/failed/cancelled/completed-missing-report state rendering; no change to polling ownership/cancellation semantics.
- Correct low-source warning in ko/en; next check becomes passive family-specific investigation, with mitigations retained in the existing secondary approved-response section.
- Do not yet invent guide DTOs or fixtures; new guide UI follows producer B.

### B. Offline candidate producer and durable contract
Files likely: analysis/src/c2hunter_analysis/pcap_attack_guidance.py (new), ddos_attack.py; controller/src/c2hunter_controller/pcap_attack_guidance_schema.py (new), app.py and any actual shared result projection needed; sensor/worker/src/c2hunter_worker/analysis.py. Add unique analysis/controller/worker tests and producer-generated fixtures under tracked test fixture locations.
- First preserve low-source warning alongside findings with a focused RED→GREEN case.
- Implement candidate collector with sequential vertical RED→GREEN slices: single/low-source SYN, mixed background retaining a local SYN window, relative UDP below old floor, short excerpt, normal payload/handshake/stable-low-UDP controls, then bounded/unsupported/owner/serialization cases.
- Trace real staged upload→preparation→worker→result persistence→API readback and reanalysis. No schema migration should be needed for a versioned JSON job artifact; verify actual repository paths rather than assume.
- Freeze exact producer-generated valid bytes and a closed schema/registry. Keep v1–v4 reports and their exports/AI contracts valid. Existing DDoS fixture assertions are not weakened to accommodate the guide.

### C. Strict consumer and human guidance
Files likely: web/src/pcapAttackGuidance.ts and PcapAttackGuidance.tsx (new), App.tsx integration, focused tests and producer-fixture parity. Backend/producer files are read-only to this writer.
- Consume producer-generated exact bytes; unknown/malformed/foreign/missing-present data fails safely. Absent historical guide is distinct from zero candidates.
- Lead with review summary and target/time/pattern/why/uncertainty/next check; clearly separate qualified DDoS verdict and optional AI interpretation. Preserve all candidate access through pages of8 and one lazy detail owner; visible coverage warnings, ko/en.
- Evidence provides validated target/port/protocol/time/source examples and counters. Do not invent packet-index links or claim all matching packets are malicious. Existing signature/export actions remain on their original owned DDoS findings.

### D. Integration, review and acceptance
- Reconcile exact source deltas and independently review the combined behavior, producer→Python→Web acceptance, negative controls, caps and preservation.
- Fresh focused real-PCAP API/worker/schema tests, saved producer-byte browser validation and local real-browser workflow on isolated owned resources. Production9001 is not updated by these tests.
- Run canonical make test and make lint after the final edit; source Python/Go/Web/native build and available Docker packaging separately. Use existing caches, no downloads. Missing cached packaging dependencies remain explicitly unverified, not a substituted source-build PASS.
- Preserve failed probes and all original regression assertions. Full canonical runs have historically taken hours; run cheap downstream/static/preflight checks before the one final frozen replay. Reuse previous passing evidence only for the unchanged baseline audit, never as final verification of modified source.

Completion requires executable candidate examples reaching the actual upload/worker/API/UI path, retained negative controls and legacy behavior, truthful omission/coverage, and no unrelated changes. A nicer screen alone does not close the discovery gaps. Report source acceptance separately from deployment and actual live use.
