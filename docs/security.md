# Security

## Scope and threat model

C2Hunter is defensive passive analysis. It does not contact a candidate, bypass authentication, control endpoints, scan the Internet, decrypt TLS, or replay attacks. Traffic metadata and PCAP may contain personal, credential, or organizationally sensitive data and must be handled as restricted evidence.

Threats include malicious sensor enrollment, stolen credentials, forged telemetry, parser/resource exhaustion, path traversal in export, unauthorized PCAP access, dependency compromise, secret leakage, tampered evidence, and administrator misuse.

## Identity and authorization

Human users authenticate with Bearer tokens. Sensors authenticate with `X-Sensor-Token` headers
and credential hashes stored in PostgreSQL — they do not participate in the RBAC role hierarchy.

### Roles and minimum privilege

The Controller defines three roles (`security.py:14-17`):

| Role   | Privilege | Typical use                              |
|--------|-----------|------------------------------------------|
| VIEWER | 1         | Read analysis results, flows, dashboard  |
| ANALYST| 2         | Create jobs, cancel/reanalyze, export    |
| ADMIN  | 3         | Enrollment, sensor config/rotate/revoke, settings |

Every human API route enforces a minimum role (`security.py:140-164`).
`GET` defaults to `VIEWER`; job creation and candidate mutations require `ANALYST`;
`sensor-enrollments`, `sensor-groups`, `detector-weight-presets`,
`sensors/{id}/configuration|rotate|revoke` require `ADMIN`.

Health checks (`/api/v1/health`, `/ready`, `/metrics`), the dev-login endpoint,
and sensor-specific routes (heartbeat, flow-batches, pcap-segments, agent-config) skip role checks.

### Static token configuration

Configure only SHA-256 hex digests (`security.py:70-99`):

```
C2HUNTER_VIEWER_TOKEN_SHA256=..64 hex chars..
C2HUNTER_ANALYST_TOKEN_SHA256=..64 hex chars..
C2HUNTER_ADMIN_TOKEN_SHA256=..64 hex chars..
```

Plaintext tokens must never appear in `.env`. The Controller compares digests with
`hmac.compare_digest` for constant-time equality (timing-attack safe).
Keep plaintext tokens in an external secret manager and rotate them periodically.
Authentication is fail-closed: outside `C2HUNTER_ENVIRONMENT=test`,
`api_auth_required` defaults to `true` (`config.py:44-46`).

### Sensor authentication (separate from RBAC)

Sensors use enrollment-based credentials. After enrollment and claim, the Controller stores
a per-sensor credential hash in PostgreSQL. Every sensor API call includes an `X-Sensor-Token`
header; the Controller validates it with `hmac.compare_digest` against the stored hash
and checks revocation status (`app.py:665-678`). Sensors do not map to VIEWER/ANALYST/ADMIN roles.

### Development login

POST `/api/v1/auth/dev-login` is a local-convenience endpoint (`app.py:631-656`).
When `C2HUNTER_DEV_LOGIN_ENABLED=true`, it mints a short-lived in-memory session with
fixed `ADMIN` role and configurable TTL (`C2HUNTER_DEV_TOKEN_TTL_SECONDS`,
1~86400 초, 기본 28800 초/8시간).
The response includes `access_token`, `token_type: bearer`, `expires_in`, `username`,
`role: ADMIN`, and a `limitations` disclaimer. Disabled environments return HTTP 404
(not 403) to avoid fingerprinting. Sessions live only in process memory — they expire on
Controller restart or TTL expiry. Disable `C2HUNTER_DEV_LOGIN_ENABLED` outside local
development and use OIDC/MFA instead.

### Rate limiting

Three endpoints are rate-limited per-process with fixed-window counters
(`security.py:103-127`, configured in `.env.example:23-26`):

| Endpoint                 | Key        | Default limit  | Window   | Override env                          |
|--------------------------|------------|----------------|----------|---------------------------------------|
| `/auth/dev-login`        | Client IP  | ≤10 requests   | 60 s     | `C2HUNTER_DEV_LOGIN_RATE_LIMIT`       |
| Enrollment claim         | Client IP  | ≤10 requests   | 60 s     | `C2HUNTER_ENROLLMENT_CLAIM_RATE_LIMIT`|
| Analysis job creation    | Auth subject | ≤30 requests | 60 s     | `C2HUNTER_ANALYSIS_JOB_RATE_LIMIT`    |

Window duration is set by `C2HUNTER_RATE_LIMIT_WINDOW_SECONDS` (default 60, max 3600).
When the limit is exceeded, the Controller returns HTTP 429 with a `Retry-After` header
(second count until window head expires). These are per-process safeguards — use
ingress-level or Redis-backed distributed limiting for multi-replica production.

## Secret management

`.env.example` contains names and deliberately unusable development placeholders. Real values and all `*.key`, `*.pem`, `*.p12` files are ignored. Inject production secrets with a secret manager/read-only mount, scope and rotate them, and prevent their appearance in logs, URLs, crash dumps, fixtures, images, CI artifacts, and shell history. A leaked key requires revocation and audit, not only deletion from Git.

## PCAP and privacy

Payload/PCAP retention is opt-in and shortest-necessary. Prefer flow statistics and hashes. Validate scalar and nested export filters, source provenance, cumulative packet/byte limits, and retained-object digests before creating bounded output. Generate object keys and filenames server-side and authorize both creation and Controller-mediated download. Audit request/result/bytes without storing payload in audit records. Use encryption at rest and restricted backup access.

Offline uploads are untrusted binary input. The Controller enforces a byte limit before buffering, a packet-count limit while parsing, validates PCAP/PCAPNG block lengths and timestamps, supports only explicit link types, and strips client path components from the displayed filename. Keep the defaults conservative, reject unsupported media types, and never invoke external packet tools or contact addresses found in a capture. Uploaded packet bytes are restricted evidence and follow the analysis-result retention policy.

Analysis metadata edits cannot alter source data, time range, detector settings, evidence, or scores. Job deletion is limited to terminal jobs and removes the associated candidates and generated exports; require an explicit UI confirmation and retain the append-only deletion audit in production.

## Input and resource defenses

Validate REST/Pydantic and protobuf fields, normalized IP/CIDR/domain/fingerprint values, BPF policy, pagination limits, capture packet/byte/time limits, decompression/object size, checksums, and schema versions. Use bounded chunks/queues, timeouts, quotas, retry backoff, and idempotency ledgers. Never interpolate user input into paths, object keys, SQL, shell commands, or `Content-Disposition` filenames.

## Audit and integrity

Append-only audits cover login, analysis create/cancel/reanalysis, PCAP export/download, allowlist, sensor enrollment/removal, settings, roles, and deletion. Record UTC time, actor, source IP, request ID, action, target, and result. Protect audit retention (default 365 days) and clock synchronization. Preserve detector version, parameter/allowlist snapshot, object checksum, loss/skew warning, and state transitions so a result can be reproduced and challenged.

## Network and container hardening

Expose only the HTTPS ingress. Keep PostgreSQL, Redis, ClickHouse, MinIO, Worker, and sensor gateway private. Use non-root containers, read-only roots where supported, dropped capabilities, resource limits, and separate service accounts. Live sensor capture receives only required capabilities (`CAP_NET_RAW`, optionally `CAP_NET_ADMIN`) rather than root. Pin release images by digest and patch on a measured schedule.

## CI security gates

`.github/workflows/ci.yml` runs production npm audit, Python dependency audit, Gitleaks, and Trivy after lint→unit→integration→build. It scans source and dependencies; deployment should additionally scan built image digests and generate an SBOM/signature. A high/critical finding blocks release unless a documented, time-bounded risk exception identifies reachability, owner, and remediation date.

## Incident response

1. Isolate affected credential/service without deleting evidence.
2. Revoke user/session/sensor/object credentials and rotate related secrets.
3. Preserve audit logs, image digests, configuration, timestamps, and object checksums.
4. Determine unauthorized access/export and fulfill notification obligations.
5. Patch/rebuild from pinned clean inputs, restore only validated data, and monitor recurrence.
6. Document root cause and update controls/tests.

Report vulnerabilities privately to the repository security contact; do not include real PCAP, credentials, or candidate infrastructure in a public issue.
