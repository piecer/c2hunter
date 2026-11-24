# Authentication operations

Named accounts provide **shared-team RBAC, not tenant isolation**. VIEWER can read
permitted stored results; ANALYST adds permitted analysis and external lookups;
ADMIN adds account administration and privileged domain operations. Existing
route-specific restrictions still apply. Investigations retain their existing
private owner checks, including for administrators. Named accounts cannot take
over privately owned investigations or adopt unscoped legacy exports. Ordinary
analysis jobs remain shared. There is no public signup, web first-admin bootstrap,
MFA, SSO, or account rename/delete operation.

## Configuration and origin

| Setting | Deployment behavior |
| --- | --- |
| `C2HUNTER_ACCOUNT_AUTH_ENABLED` | Compose defaults to `true`; explicit `false` opts out across all controller-image services. Outside Compose, defaults on except in `test`. |
| `C2HUNTER_API_AUTH_REQUIRED` | Keep `true`; deployable anonymous mode is rejected. |
| `C2HUNTER_DEV_LOGIN_ENABLED` | Defaults `false`. Account mode rejects `true`. |
| `C2HUNTER_AUTH_PUBLIC_ORIGIN` | Exact browser UI origin: scheme, lowercase hostname and non-default port, with no path, trailing slash, query or credentials. Unset/empty means setup required, not anonymous access. |
| `C2HUNTER_AUTH_INSECURE_LOOPBACK_HTTP` | Defaults `false`. Explicit `true` permits HTTP only for loopback origins, never remote plaintext login. |
| `C2HUNTER_DATABASE_URL` | Compose supplies the same PostgreSQL DSN to controller-image consumers. Auth has separately versioned tables in that database; no SQLite fallback on failure. |
| `C2HUNTER_AUTH_DATABASE_PATH` | Non-Compose `memory://` application deployments use private persistent SQLite, default `data/security/auth.sqlite3`. Not a PostgreSQL fallback or a Compose per-worker database. |
| `C2HUNTER_AUTH_AUDIT_RETENTION_DAYS` | Defaults to `180`; integer range `1`–`3650`. Compose propagates it to the controller, which owns maintenance. Empty Compose values use `180`; invalid values fail settings validation. |

Use HTTPS in production, terminate TLS at a maintained reverse proxy, and expose
only that frontend. Keep the controller and storage private; the development
Compose port mappings are not production network isolation. Configure the origin
for the **UI**, not the controller's internal address. Preserve the original Host,
including its non-default port, through every proxy hop. Trust only the immediate
proxy CIDRs via `C2HUNTER_TRUSTED_PROXY_CIDRS`; do not trust arbitrary forwarded
client addresses. Browser requests are same-origin and writes use session-bound
CSRF. Session cookies are HttpOnly, SameSite=Lax and Secure with HTTPS.

For an explicitly local development UI only:

```dotenv
WEB_PORT=9001
C2HUNTER_AUTH_PUBLIC_ORIGIN=http://127.0.0.1:9001
C2HUNTER_AUTH_INSECURE_LOOPBACK_HTTP=true
```

Open that exact origin, not `localhost` or the controller port. `WEB_PORT` defaults
to `8080`; `9001` above is an example, not a new default. Keep this development
listener restricted to the local machine. An HTTPS origin such as
`https://hunter.example.test:9443` must likewise match the externally visible port;
omit default ports (`:443` for HTTPS).

## First installation: explicit local bootstrap

The following are operator commands, **not automatic startup hooks**. Provision
required database/object-store secrets privately and use images matching the
source first. Do not put passwords, bearer values or DSNs in shell arguments,
logs, documentation or Git. The commands below use an operator-owned `.env`;
production should inject secrets through the deployment's secret manager.

1. Set the account/origin configuration above and keep development login disabled.
   Validate the manifest without printing resolved secrets:

   ```sh
   docker compose --env-file .env config --quiet
   ```

2. Start core dependencies, then run the existing core migration explicitly:

   ```sh
   docker compose --env-file .env up -d postgres redis clickhouse minio
   ```

   Wait for dependency health before continuing:

   ```sh
   docker compose --env-file .env run --rm --no-deps postgres-migrate
   ```

   Stop if any step fails.

3. Initialize the separate auth schema, then create the first administrator from
   a trusted interactive terminal:

   ```sh
   docker compose --env-file .env run --rm --no-deps controller \
     python -m c2hunter_controller.auth_cli init
   printf 'First administrator username: '
   read -r C2HUNTER_BOOTSTRAP_USERNAME
   docker compose --env-file .env run --rm --no-deps controller \
     python -m c2hunter_controller.auth_cli bootstrap "$C2HUNTER_BOOTSTRAP_USERNAME"
   ```

   `bootstrap` works only while the users table is empty. There is no built-in
   administrator or default password. Passwords are entered twice using hidden
   `getpass` prompts; no password arguments or redirected-stdin fallback are
   accepted. Keep the interactive TTY (do not add `-T`). Usernames use 1–64 ASCII
   letters, digits or `_.@-`, unique without regard to case. Passwords require
   12–128 characters and at most 512 UTF-8 bytes.

4. Only after both migrations and bootstrap succeed, start the application:

   ```sh
   docker compose --env-file .env up -d \
     controller worker pcap-export-worker pcap-offset-index-worker web
   ```

   If AI work is configured, separately enable its existing profile:
   `docker compose --env-file .env --profile ai up -d ai-worker`.
   Check `/api/v1/ready` and sign in through the configured UI origin.

HTTP startup and the core migration do **not** initialize auth schema or create
users. Missing/incompatible auth storage or missing origin fails protected human
operations closed; safe setup/health/device paths are not a bootstrap backdoor.
Do not bypass readiness by disabling API authentication.

Outside Compose, the same `python -m c2hunter_controller.auth_cli` commands read
exported `C2HUNTER_DATABASE_URL` and `C2HUNTER_AUTH_DATABASE_PATH`; the CLI does not
load `.env`. Ensure CLI, API and workers select the same persistent store. For
`memory://`, use an absolute SQLite path on persistent storage: the parent must be
owned mode `0700`, and an existing file owned mode `0600`, regular and not linked.
Unsafe pre-existing paths are refused, not silently chmodded. Never initialize a
separate local database to mask a PostgreSQL error.

## Accounts, sessions and recovery

Administrators create accounts, change roles/active state, reset passwords and
revoke sessions through account administration. These endpoints require a named
ADMIN session, not a static admin bearer. Created and reset accounts must change
their password before using the application. The bootstrap administrator is not
forced to change the password just chosen locally.

- Self-service password change requires the current password, revokes **all** of
  that user's sessions including the current one, and requires sign-in again.
- Password resets, role changes and active-state changes invalidate existing
  sessions; even a no-op account update invalidates them. Disabling an account
  prevents login. Session revocation does not cancel work already admitted under
  the original actor.
- Users can list/revoke their own sessions; administrators can revoke all sessions
  for a selected user. Logout revokes the current session. Server expiry is
  30 minutes idle and 12 hours absolute, not an indefinitely renewable cookie.
- The last active administrator cannot be disabled or demoted (`LAST_ADMIN`, 409).
  Keep another trusted administrator for operational continuity.
- For local password recovery, use the same deployment and database configuration:

  ```sh
  printf 'Account username to reset: '
  read -r C2HUNTER_RESET_USERNAME
  docker compose --env-file .env run --rm --no-deps controller \
    python -m c2hunter_controller.auth_cli reset-password "$C2HUNTER_RESET_USERNAME"
  ```

  This uses confirmed hidden prompts, revokes old sessions and forces password
  change at next login. It does not create or reactivate an account.

## Audit and incomplete work

Users read their own activity at `GET /api/v1/auth/activity`; administrators read
team security events at `GET /api/v1/admin/audit`. Filters include user, action,
outcome, target and finite UTC epoch `since`/`until` values. Own activity cannot be
redirected to another actor. Events omit passwords, token/hash material and raw
request bodies. Audit history is not tamper-proof against the database owner.

### Automatic retention

With account mode enabled, each controller app owns one maintenance task. It
awaits one off-loop pass during startup, then waits **3600 seconds after each
completed pass** before the next. There is no catch-up loop, overlapping pass or
retention worker in the standalone job services. Disabling account mode disables
maintenance, including for an injected store. Shutdown stops further admission
and drains an already accepted SQL callback before dependent teardown. A real app
lifespan exit owns the entire existing shutdown chain: repeated cancellation is
propagated only after that chain finishes, without requiring the caller to retry.
Startup cancellation also drains accepted native work; cancellation cannot
forcibly interrupt a database callback. A later normal lifespan of the same app
creates a fresh maintenance owner only after the previous owner has drained,
including when the new lifespan runs on a different event loop. Each fresh owner
performs its startup pass and resumes the same hourly schedule; stopped individual
owners remain single-use. Cleanup errors still propagate; when cancellation is
already primary, a secondary cleanup error is logged without exception text.

The default retention is **180 days**, configurable as above. Each pass deletes
at most **1000 eligible events**, oldest first by `(timestamp, id)`, strictly older
than the cutoff; a timestamp exactly at the cutoff is retained. The deletion and
one system `audit.prune` event with `details={"count": N}` commit together. Audit
insertion failure rolls back the deletions. Like the inspected tracedns reference,
a successful zero-deletion pass also records `count=0` (one event per pass).

**Lifecycle-evidence exception:** events referenced by any `auth_job_links.intent_id`
or `event_id` are retained regardless of age. Links are never deleted to make
events eligible; this preserves pending ownership and terminal deduplication.
Non-HTTP `started` evidence is conservatively retained. An HTTP `started` event is
eligible only when a terminal `succeeded`, `failed`, `denied` or `cancelled` event
with the same request ID, action, target, actor ID and authentication kind exists
at an equal/later timestamp. Missing request IDs and `unknown` outcomes do not
prove completion. Maintenance does not reconcile or terminate another worker's
live work. Evidence without such proof can remain indefinitely, even if its
completion evidence has already aged out; this is not a strict all-records TTL.

Protected rows are filtered **before** the 1000-row limit, so a prefix of protected
evidence does not consume the deletion allowance. Backlogs, protected evidence,
service downtime and failed maintenance can extend actual retention beyond the
configured age. SQL may examine more than 1000 index entries to find eligible
rows; the limit bounds deleted/returned rows, not all database work. PostgreSQL's
existing statement/lock timeouts still apply; SQLite retains its existing lock
wait. No unbounded result set is loaded into Python.

Existing `auth_audit_order` and `auth_job_pending` indexes support age ordering and
terminal-link checks. Explicit `auth_cli init` additionally creates the
`auth_job_intent` and `auth_audit_http_terminal` lookup indexes, including on an
already-initialized version-1 store, without changing users or the HMAC key. Run
that explicit initialization step when upgrading to install the indexes. HTTP
startup, readiness and retention **never execute DDL** or initialize missing
storage; an old version-1 store remains compatible but may scan more without the
new indexes.

PostgreSQL maintenance needs **DELETE on `auth_audit` in addition to the existing
runtime SELECT/INSERT rights**. It needs no DELETE on `auth_job_links` and no DDL
rights. Provision this maintenance-only privilege explicitly for the controller
runtime role if using restricted grants. Its absence is not a new prerequisite
for core account readiness or other HTTP operations: the maintenance transaction
fails safely, logs `Audit retention maintenance failed`, and retries next hour
while the app remains running. Raw exception/DSN text is never logged by this task.
`app.state.auth_retention.last_error` is the bounded internal status
`AUDIT_RETENTION_FAILED` (or `None` after success), and `last_deleted` is the last
successful pass count or `None` after failure. This state is separate from HTTP
readiness; monitor maintenance errors and `audit.prune` history to detect lag.


`POST /api/v1/admin/audit/export` exports **one bounded JSONL page**, not a complete
backup: default `limit=50`, maximum `1000`, `offset` from `0` to `10000000`. It
requires the admin session, matching Origin and CSRF. Preserve `X-Total-Count` and
`X-Next-Offset`; an empty next-offset header means no next page at that observation.
Request each additional page explicitly with the same filters. This is a live
offset-paginated view, not a frozen snapshot. Export is itself audited.

Audit unavailability prevents new protected mutations/external work. A terminal
audit failure after domain work committed does not mean rollback: do not blindly
resubmit. HTTP operation audit records admission/publication, not proof of all
streamed bytes reaching the client; background completion must use the original
persisted actor and winning terminal state.

The bounded maintenance command is:

```sh
docker compose --env-file .env run --rm --no-deps controller \
  python -m c2hunter_controller.auth_cli reconcile-audit --limit 100
```

The command reads one page (`--limit` 1–1000 and optional `--cursor`) using the
configured PostgreSQL metadata adapters for analysis, PCAP export, AI runs, and
IP/JOB investigations. It checks the relevant domain schema guards and creates no
blob client, schema, queue dispatcher or model work. A `memory://` domain backend
has no cross-process authority and is refused with `AUDIT_RECONCILE_UNSUPPORTED`
and exit `2`; the private SQLite account database is not a substitute for durable
domain records. Only proven terminal states are repaired. Running, queued,
missing or unprovable work remains unresolved; restarting an API worker must not
settle another worker's live jobs. Real PostgreSQL composition of these readers
remains a required integration gate, distinct from their SQLite-backed tests.

## Existing machine and device compatibility

Explicit `C2HUNTER_ACCOUNT_AUTH_ENABLED=false` retains existing static bearer
operation with `C2HUNTER_API_AUTH_REQUIRED=true` and the configured role-specific
SHA-256 token digests. Opt-out is propagated to every controller-image service,
including export/index/AI workers and the core migration service. It disables
named-account login/self-service/admin features, not the API's authentication
requirement. Development login additionally requires explicit
`C2HUNTER_DEV_LOGIN_ENABLED=true` in development/test; never use it in production.

In account mode, service bearers retain their existing domain roles but cannot
manage human accounts or sessions. An explicit invalid bearer is not rescued by a
cookie; combining both credentials is rejected. Keep automation credentials
separate from human sessions.

Sensor enrollment, agent tokens and worker/claim authentication remain separate
and unchanged. Human cookies do not authorize device operations. The `worker`
service still uses the sensor-worker image, without a controller auth package or
new auth capabilities. PCAP preparation runs inside `controller`; there is no
separate `pcap-preparation-worker` Compose service to start or configure.
