# ZeroShield CI and Docker Release Reference (V2 Phase 6, Steps 6/8)

## 1. Continuous Integration

`.github/workflows/ci.yml` runs on every push and pull request to `master`.
**CI only - no deployment, no image publish, no release step.** Two
independent jobs:

- **`backend`**: installs ZeroShield with every extra
  (`pip install -e ".[api,dashboard,queue,storage,db,intelligence,excel,auth,ai,observability,dev]"`),
  then `ruff check src/ tests/`, `mypy src/`, `pytest tests/ -q`. No
  external services are started - the full ~1036-test suite (unit,
  integration, security, policy) runs against SQLite in-memory and
  fakes/mocks throughout; the two genuinely-real-broker/-database
  integration tests self-skip because `ZEROSHIELD_E2E_RABBITMQ_URL`/
  `ZEROSHIELD_E2E_POSTGRES_URL` are deliberately unset in CI (see
  [`docs/TESTING.md`](TESTING.md)).
- **`frontend`**: `npm ci`, `tsc --noEmit`, `npm run lint`, `npm test`
  (vitest), `npm run build`, then installs Playwright's Chromium and runs
  `npm run test:e2e` - the smoke tier only (`apps/web/e2e/smoke/`), which
  needs no backend. The live `workflows/` tier
  (`apps/web/e2e/workflows/*.spec.ts`) needs the full docker-compose stack
  and a seeded ADMIN account and is deliberately not run in CI - see
  [`apps/web/e2e/README.md`](../apps/web/e2e/README.md).

## 2. Docker Compose (one command, finalized)

```sh
docker compose up -d
```

Brings up every service: `postgres`, `rabbitmq`, `minio`, `api`, `worker`,
`intelligence-worker`, `web`, `dashboard` (legacy), `prometheus`, `grafana`.
No Redis - nothing in ZeroShield needs a cache or a pub/sub broker beyond
what RabbitMQ (job queue) and Postgres (system of record) already provide;
adding one would be unused infrastructure.

Every service that has something meaningful to check has a `healthcheck:`
(new in Phase 6 for `worker`, `intelligence-worker`, `web`, `prometheus`,
`grafana` - `postgres`/`rabbitmq`/`minio`/`api`/`dashboard` already had one),
and `depends_on: condition: service_healthy` chains accordingly, so
`docker compose up` brings services up in a correct, verified order rather
than a fixed sleep/guess.

### First-time setup after `docker compose up -d`

There is no seeded user - V2 Phase 6 local auth requires bootstrapping the
first ADMIN account:

```sh
docker compose exec api zeroshield create-admin --username <you> --password "<a strong password>"
```

Then sign in at <http://localhost:3001>. See
[`docs/SECURITY.md`](SECURITY.md) for roles and [`docs/CLI_REFERENCE.md`](CLI_REFERENCE.md#create-admin)
for the command's full behaviour.

### Overriding credentials

Copy [`.env.example`](../.env.example) to `.env` to override the default
Postgres/MinIO/Grafana passwords - every default still works with no `.env`
file at all, so this is optional for local/dev use and expected for
anything longer-lived.

### Ports

| Service | Host port | Notes |
|---|---|---|
| `web` | 3001 | Primary UI |
| `api` | 8000 | Swagger at `/docs` |
| `worker` metrics | 9200 | Prometheus scrape target |
| `intelligence-worker` metrics | 9201 | Prometheus scrape target (new in Phase 6) |
| `postgres` | 5433 | Not 5432, to avoid colliding with a host Postgres |
| `rabbitmq` (AMQP / management UI) | 5673 / 15673 | Not 5672/15672, same reasoning |
| `minio` (API / console) | 9002 / 9003 | Not 9000/9001, same reasoning |
| `dashboard` (legacy) | 8502 | Not Streamlit's default 8501 |
| `prometheus` | 9090 | |
| `grafana` | 3000 | Pre-provisioned dashboard + datasource |

## 3. What is deliberately not here

No Kubernetes manifests, no cloud provider config, no CD/deploy pipeline,
no image registry push. See [`docs/FUTURE_OPPORTUNITIES.md`](FUTURE_OPPORTUNITIES.md)
for what a cloud/SaaS evolution of this would look like - documented only,
not implemented, per the V2 Phase 6 scope boundary.
