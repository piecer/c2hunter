# Stored-evidence IP investigations

This path creates a separate investigation Run for one observed IPv4 or IPv6
address in an analysis job. It does not change existing candidate scores or
analysis verdicts. A candidate ID is not required; internal hosts and observed
noncandidate endpoints can also be selected. CIDR and hostname targets are not
single-IP investigation requests.

## Runtime prerequisites

- Enable the existing AI-analysis gate with `C2HUNTER_AI_ANALYSIS_ENABLED=true`
  and configure the existing AI provider/model settings. The investigation
  transport supports Ollama and OpenAI-compatible providers, not the default fake
  provider. Selecting a provider or enabling inline supervision alone is not enough.
- The application-owned supervisor is opt-in through
  `C2HUNTER_AI_INVESTIGATION_INLINE_ENABLED` (default false). The existing AI worker
  also integrates investigation supervision. Check capability and worker status;
  configuring a model is not proof that a worker or model is ready.
- The bounded transport rejects unsupported DNS aliases, including
  `host.docker.internal`; do not weaken that policy to make a deployment appear
  available. Configure an endpoint permitted by the transport and deployment.
- PostgreSQL schema changes belong to the explicit migration owner. With the
  intended database supplied securely via `C2HUNTER_DATABASE_URL`, the migration
  entrypoint is `python -m c2hunter_controller.migrate`. Do not migrate a running
  deployment without its operator's approval. Normal API reads do not perform DDL.
- New investigation routes require an authenticated ANALYST-or-higher principal.
  A run identifier alone does not grant access to another owner's history.

## API and UI

`GET /api/v1/ai-investigations/capabilities` exposes availability. Unavailable
responses may carry `x-investigation-unavailable-reason`; do not treat refusal as
an empty successful investigation.

The job-scoped base is `/api/v1/analysis-jobs/{job_id}/ai-investigations`:

- `POST /source-preview` checks the requested observation scope.
- `POST` admits a source-bound, idempotent request; `GET` pages saved runs.
- `GET /{run_id}` reads current state; `GET /{run_id}/steps` pages tool history.
- `GET /{run_id}/evidence/{evidence_id}` reads retained cited evidence.
- `POST /{run_id}/cancel` requests cancellation of that exact run.

Use the IP investigation panel in analysis details, or candidate/flow endpoint
buttons. Preview the scope before starting. Results separate stored facts from AI
interpretation and expose counterevidence, limitations, next checks and evidence
links. Failed status reads remain uncertain until an accepted read or cancellation
response supplies current state. Cancellation acknowledgment does not prove that
an in-flight provider computation has stopped or physical worker capacity is free.

## Interpretation and limits

The five read-only tools are `peer_overview`, `peer_timeline`,
`peer_flow_samples`, `peer_protocol_observations` and `compare_peer_cohort`.
They use bounded stored observations, not arbitrary SQL, shell commands, target
connections, external TI lookups or raw-payload disclosure. The server owns scope,
call/read/output budgets, evidence validation and publication fencing.

Missing fields, partial inspection and unavailable sources are not observations of
zero. Failure to find an IP in inspected rows is not proof of source-wide absence.
Progress counters include upper-bound source-byte reservations rather than a claim
of measured network transfer. Model identity is captured per run; a model tag is
not a verified weights digest. Historical results must not be relabeled with the
current model configuration.

Unit and scripted-provider/browser checks establish contract and integration
behavior, not real-model detection quality. Real local-model comparison uses a
separate generated-data evaluation stage. Neither that evaluation nor an isolated
browser run establishes operating-deployment or LIVE-sensor acceptance.
