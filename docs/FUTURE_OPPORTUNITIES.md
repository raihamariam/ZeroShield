# Future Opportunities (documentation only)

V2 Phase 6 is explicitly the final implementation phase of this engagement -
"do not implement cloud, Kubernetes, SaaS, or other future-opportunity
work." This document exists to record where a future team could reasonably
take ZeroShield next, entirely as reference; nothing described below is
implemented, scheduled, or assumed by any code in this repository.

## 1. Cloud deployment

The current Docker Compose setup is single-host by design (see
[`docs/DEPLOYMENT.md`](DEPLOYMENT.md)). A cloud deployment would need:

- A managed Postgres (RDS/Cloud SQL) replacing the `postgres` container -
  the schema (Alembic migrations under `alembic/versions/`) is already
  vendor-neutral SQL, so this is largely a connection-string change.
  `DATABASE_URL` is already the only coupling point.
- A managed object store (S3/GCS) in place of MinIO -
  `zeroshield.repositories.MinioEvidenceRepository` already speaks the S3
  API, so this is close to a drop-in swap; evidence immutability guarantees
  would need re-verifying against the target provider's actual consistency
  model.
- A managed message queue (Amazon MQ, CloudAMQP) or a queue abstraction
  layer if RabbitMQ specifically isn't available managed in the target
  environment.
- Secrets management (the current `.env`/environment-variable model is
  fine for a single host; a cloud deployment should move
  `POSTGRES_PASSWORD`/`MINIO_ROOT_PASSWORD`/`GRAFANA_ADMIN_PASSWORD`/session
  signing material into a real secrets manager).

## 2. Kubernetes

The existing "worker(s)" model (`worker`/`intelligence-worker` as separate
Compose services, each single-instance) maps naturally to Deployments with
`replicas: N` and a `HorizontalPodAutoscaler` keyed on RabbitMQ queue depth
- both queues already have `prefetch_count=1`, so horizontal scaling is
just "run more consumers," no code change needed. The API is already
stateless (sessions live in Postgres, not in-process), so it's also a
straightforward Deployment + Service + Ingress. The Phase 3 `SandboxExecutor`
(local allow-list/timeout/network-guard/resource-limit sandbox) would be
the one component worth reassessing first - a cluster gives access to
stronger per-job isolation primitives (gVisor/Kata/Firecracker microVMs,
or a dedicated Job-per-execution model) than a local subprocess sandbox
can provide.

## 3. SaaS / multi-tenancy

The current auth/RBAC model (`docs/SECURITY.md`) is single-organisation:
four roles, no tenant/organisation dimension. A SaaS evolution would need:

- A `tenant_id` (or `organisation_id`) column threaded through every table
  that currently has no concept of "whose data this is" (experiments,
  assets, controls, vulnerabilities, audit events, sessions) plus
  tenant-scoped uniqueness constraints and query filters everywhere.
- Per-tenant resource limits (concurrent runs, storage) - none exist today
  because there is only one tenant.
- Billing/usage metering - the Prometheus counters already introduced
  (`docs/OBSERVABILITY.md`) are a reasonable starting signal source
  (`zeroshield_experiment_runs_submitted_total`, etc.) but were designed as
  operational telemetry, not billing-grade metering, and would need an
  audit-quality event source instead (the `audit_events` table is closer,
  but was designed for security traceability, not usage accounting).

## 4. SSO / enterprise identity

Local Argon2id auth (`docs/SECURITY.md` §1) is intentionally simple for a
single-organisation local deployment. An enterprise rollout would want:

- SAML/OIDC federation (Okta, Azure AD, Google Workspace) - would sit
  alongside, not replace, local auth (`zeroshield.auth.service.AuthService`
  already isolates session creation from credential verification, so a new
  `IdentityProvider` implementation could plug in at that seam without
  touching session/RBAC/audit code).
- SCIM provisioning to sync roles from an external directory instead of
  the current `/users` admin UI.
- MFA/step-up auth for ADMIN actions specifically (user creation, role
  changes) - the audit trail already records every such action with an
  actor and timestamp, which is exactly the substrate an MFA-enforcement
  policy would need to reference.

## 5. Other reasonable extensions

- **Multi-region evidence replication** - evidence immutability
  (content-addressed manifests, SHA-256 verification) already gives a
  correctness property that's easy to replicate safely (verify-on-read
  works identically regardless of which region served the bytes).
- **A managed OTLP backend** (Grafana Cloud Tempo, Honeycomb, etc.) wired
  via `OTEL_EXPORTER_OTLP_ENDPOINT` - no code change needed, purely a
  deployment/configuration decision (`docs/OBSERVABILITY.md` §3).
- **Webhook/Slack notifications** for revalidation triggers and approval
  requests - the deterministic revalidation-trigger engine
  (`zeroshield.assurance`) already computes exactly the events that would
  drive such notifications; nothing currently subscribes to them.
