# ZeroShield Security Reference (V2 Phase 6)

Covers what V2 Phase 6 ("Hardening & Final Local V2 Release") added: local
authentication, role-based access control, the immutable audit trail, and
the security test suite. This is additive to, and never weakens, the
Phase 1-5 safety controls in [`docs/HANDOVER.md` §5](HANDOVER.md#5-safety-controls)
(`SafetyPolicy`, evidence immutability, the sandbox) - those remain the
system's core defensive property; this document covers who is allowed to
*reach* them and how that is recorded.

## 1. Authentication

Every route except `GET /health`, `GET /metrics`, and `POST /auth/login`
requires an authenticated session (`zeroshield.api.dependencies.get_current_user`,
enforced per-request - never a client-side-only gate).

- **Passwords**: Argon2id (`argon2-cffi`), never stored or logged in plain
  text. `zeroshield.auth.passwords`.
- **Sessions**: opaque, server-generated tokens; the database stores only a
  SHA-256 hash of the token, never the token itself - a database read alone
  cannot forge a valid session cookie. Sessions are `HttpOnly`, `SameSite=Lax`,
  and expire after 12 hours (`SESSION_TTL`, `zeroshield.auth.service`).
- **Username-enumeration resistance**: a login attempt against a
  non-existent username still runs a full Argon2 hash-verify against a fixed
  dummy hash before responding, and every failure path returns the same
  generic `invalid username or password` message - an attacker cannot tell
  "wrong password" from "no such account" by response content or timing.
- **Account lockout**: 5 consecutive failed attempts locks the account for
  15 minutes (`MAX_FAILED_LOGIN_ATTEMPTS`, `LOCKOUT_DURATION`).
- **Bootstrapping the first account**: there is no seeded/default user.
  Create the first ADMIN via the CLI - see
  [`docs/CLI_REFERENCE.md`](CLI_REFERENCE.md#create-admin) - then create
  everyone else from the web app's Users page.

## 2. Roles and RBAC

Four roles, no implicit hierarchy - every route names its exact allowed
roles explicitly (`zeroshield.api.dependencies.require_role`); nothing is
"ADMIN can do everything a REVIEWER can" by default, though in practice
ADMIN is included everywhere as the operational escape hatch.

| Role | Intent |
|---|---|
| `viewer` | Read-only access to every GET route. Cannot reach any mutating route. |
| `researcher` | Drafts/edits experiment versions, submits AI Research Analyst requests, creates assets, triggers intelligence syncs and revalidation scans. |
| `reviewer` | Reviews/approves/rejects experiment versions, decides revalidation candidates, marks AI assessments reviewed. |
| `admin` | User management, audit trail access, and an override on self-approval (below). Included on every RESEARCHER/REVIEWER route too. |

Route -> allowed-role matrix (see `require_role(...)` call sites for the
authoritative version - this table is a snapshot):

| Route family | Allowed roles |
|---|---|
| `POST/PATCH /users*` | ADMIN |
| `GET /audit-trail` (`/audit` route) | ADMIN |
| `POST /experiment-versions`, edit, submit-review, `POST .../runs` | RESEARCHER, ADMIN |
| `POST .../start-review`, `/approve`, `/reject`, `/retire` | REVIEWER, ADMIN |
| `POST /datasets/generate` | RESEARCHER, ADMIN |
| `POST /experiments/{id}/runs` (V1-style direct submission) | RESEARCHER, REVIEWER, ADMIN |
| `POST /vulnerabilities/{cve}/analyst/*` (AI requests) | RESEARCHER, REVIEWER, ADMIN |
| `POST /assets`, `PATCH /assets/{id}` | RESEARCHER, ADMIN |
| `POST /controls/{id}/regression/explain` | RESEARCHER, REVIEWER, ADMIN |
| `POST /intelligence/sync` | RESEARCHER, ADMIN |
| `POST /revalidation`, `/revalidation/scan` | RESEARCHER, REVIEWER, ADMIN |
| `POST /revalidation/{id}/approve`, `/dismiss` | REVIEWER, ADMIN |

Every route not listed here (all `GET` list/detail routes other than
`/audit-trail`) only requires an authenticated session, any role.

Enforcement is exclusively server-side. The web app *mostly* hides controls
a caller's role can't use (better UX), but that is never the security
boundary - `tests/security/test_rbac_hardening.py` calls every mutating
route directly as a VIEWER and as an unauthenticated caller and asserts
403/401 on all of them, independent of what the UI shows. One known,
cosmetic gap found during the final release verification pass: the
Integrations page's "Trigger sync" button is not role-gated client-side (a
VIEWER sees it, unlike e.g. the Users page's "Create user" button which is)
- clicking it still 403s, since the server-side check is unconditional.
Worth a small frontend fix, not a security issue.

## 3. Self-approval blocking

A REVIEWER (or RESEARCHER) who created an experiment version cannot also
approve it - `current_user.username == version.created_by` is checked at
the `APPROVED` transition (`zeroshield.api.routes.studio._do_transition`)
and rejected with `403 self_approval_forbidden`, recording
`Action.EXPERIMENT_VERSION_SELF_APPROVAL_BLOCKED`. ADMIN is an intentional,
explicit override (an ADMIN both creating and approving is still logged
normally as `EXPERIMENT_VERSION_APPROVED`, actor = that ADMIN) - there is no
second-approver requirement above ADMIN. `created_by`/`reviewed_by`/`actor`
are never accepted from the request body for any state-changing route - the
actor is always the authenticated session's username, server-derived.

## 4. Audit trail

Append-only `audit_events` table (`zeroshield.audit`), one writer
(`AuditRepository.record()`), never updated or deleted via any route.
Every row: `actor_user_id`/`actor_username`/`actor_role`, `action`,
`target_type`/`target_id`, `occurred_at`, `request_id` (correlates to the
`X-Request-ID` response header and structured log lines - see
[`docs/OBSERVABILITY.md`](OBSERVABILITY.md)), free-form `metadata`, and
optional `previous_state`/`new_state` snapshots. `GET /audit-trail` is
ADMIN-only, filterable by `action`.

Recorded action categories (`zeroshield.audit.models.Action`):

- **Session**: `auth.login_success`, `auth.login_failure`, `auth.logout`, `auth.account_locked`
- **Users**: `user.created`, `user.role_changed`, `user.deactivated`, `user.reactivated`
- **Experiment version / approval**: `experiment_version.created`, `.edited`, `.submitted_for_review`, `.review_started`, `.approved`, `.rejected`, `.retired`, `.self_approval_blocked`
- **Runs**: `run.submitted`, `run.denied`, `run.failed`
- **Evidence**: `evidence.created`, `evidence.verified`
- **Intelligence**: `intelligence.sync_initiated`
- **Configuration**: `config.changed`
- **AI**: `ai_assessment.reviewed`
- **Assets / revalidation**: `asset.created`, `asset.updated`, `revalidation_candidate.approved`, `revalidation_candidate.dismissed`

Auxiliary writes (from the worker, e.g. `run.denied`/`run.failed`) are
failure-isolated - a database hiccup while writing an audit row logs a
warning and never fails the job itself, matching the existing
`RunRepository`/`AssuranceRepository` pattern.

## 5. Security test suite (V2 Phase 6, Step 4)

All of `tests/security/` runs with no external services (SQLite in-memory +
fakes), so it runs in CI on every push - see
[`docs/TESTING.md` §The security suite`](TESTING.md#the-security-suite-testssecurity).
Phase 6 additions, on top of the Phase 1-5 suite (path traversal, evidence
immutability, malformed-queue-message robustness, dataset secret scanning,
the dangerous-primitive tripwire, dependency vulnerability scanning - all
still enforced, unweakened):

| File | Covers |
|---|---|
| `test_auth_hardening.py` | No-cookie/forged-cookie/expired-session rejection, SQLi-shaped login credentials, session tokens and password hashes never appearing in a response body or a login-failure audit event. |
| `test_rbac_hardening.py` | Every mutating route (~26) rejects a VIEWER and an unauthenticated caller; workflow-order cannot be skipped (DRAFT straight to APPROVED); a malicious/compromised AI provider's output cannot create or promote a user; core routes stay fully functional with AI disabled. |
| `test_db_backed_id_hardening.py` | Path-traversal-, SQLi-, XSS-, and oversized-shaped path IDs across every DB-backed `{id}` route degrade to a clean 404/422, never a 500 or another record's data; a SQLi-shaped free-text `asset_id` round-trips as an inert literal string. |
| `test_minio_object_key_safety.py` | A malicious experiment_id becomes a literal S3 key (no directory-traversal semantics in a flat object namespace); a traversal-shaped `run_id` is rejected at the Pydantic domain-model layer before ever reaching a repository. |

## 6. What Phase 6 deliberately left alone

- **The CLI's `run`/`compare`/`verify-evidence` commands are unauthenticated
  and unaudited by design.** They execute in-process on the local machine
  requiring the same OS-level access as reading `DATABASE_URL` directly -
  RBAC/audit exist to govern the *network-facing* API surface multiple
  people share, not a single operator's own shell. `create-admin` is the one
  CLI command that does write an audit row (`actor_username="cli:create-admin"`).
- **The Streamlit dashboard remains unauthenticated**, unchanged from the
  Phase 4 decision already documented in its own module docstring
  (`src/zeroshield/dashboard/app.py`): it is read-only (browsing
  experiments/results/evidence, generating an Overleaf export) and its
  run-execution path was already disabled in Phase 4 specifically so it
  cannot bypass the web app's approval-gated workflow. It calls
  `zeroshield.services.experiment_service` directly, never the authenticated
  API, so it sits outside this session model entirely rather than being an
  unguarded hole inside it. See [`docs/HANDOVER.md` §6](HANDOVER.md#6-where-to-look-next)
  for the recommendation to retire it in favour of the web app.
