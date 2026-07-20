# Security

## Scope and threat model

C2Hunter is defensive passive analysis. It does not contact a candidate, bypass authentication, control endpoints, scan the Internet, decrypt TLS, or replay attacks. Traffic metadata and PCAP may contain personal, credential, or organizationally sensitive data and must be handled as restricted evidence.

Threats include malicious sensor enrollment, stolen credentials, forged telemetry, parser/resource exhaustion, path traversal in export, unauthorized PCAP access, dependency compromise, secret leakage, tampered evidence, and administrator misuse.

## Identity and authorization

- Require HTTPS for users/API and outbound mTLS for each Sensor.
- Assign unique certificate identity and `SENSOR` role; verify SAN/EKU, expiry, chain, and revocation.
- Enforce `ADMIN`, `ANALYST`, `VIEWER`, and `SENSOR` on the server and per resource. UI visibility is not authorization.
- ADMIN manages settings/users; ANALYST creates/cancels/reanalyzes and exports; VIEWER reads; SENSOR accesses sensor endpoints only.
- Disable `C2HUNTER_DEV_LOGIN_ENABLED` outside local development and use the organization's OIDC/MFA/session policy.

## Secret management

`.env.example` contains names and deliberately unusable development placeholders. Real values and all `*.key`, `*.pem`, `*.p12` files are ignored. Inject production secrets with a secret manager/read-only mount, scope and rotate them, and prevent their appearance in logs, URLs, crash dumps, fixtures, images, CI artifacts, and shell history. A leaked key requires revocation and audit, not only deletion from Git.

## PCAP and privacy

Payload/PCAP retention is opt-in and shortest-necessary. Prefer flow statistics and hashes. Validate export filters (candidate, internal host, time, port, protocol, direction, sensor), stream with size limits, generate object keys and filenames server-side, authorize both creation and download, and use short-lived signed URLs. Audit request/result/bytes without storing signed URLs or payload. Use encryption at rest and restricted backup access.

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
