import type { Metadata } from "next";
import { Badge, Card, CardBody, CardHeader, ErrorState } from "@/components/ui";
import { systemApi } from "@/lib/api";
import { formatDateTime, titleCase } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "System Health" };

async function settle<T>(p: Promise<T>) {
  try {
    return { ok: true as const, data: await p };
  } catch (error) {
    return { ok: false as const, error };
  }
}

const DEPENDENCY_DESCRIPTIONS: Record<string, string> = {
  api: "The FastAPI process itself.",
  database: "Postgres - experiment versions, approvals, run events, threat intelligence.",
  rabbitmq: "The run-job and intelligence-sync message queue.",
  worker: "The RabbitMQ consumer that executes runs. Inferred from live consumer count - there is no separate heartbeat.",
  minio: "Object storage for evidence bundles, when ZEROSHIELD_EVIDENCE_BACKEND=minio.",
};

export default async function HealthPage() {
  const [health, status] = await Promise.all([settle(systemApi.getHealth()), settle(systemApi.getSystemStatus())]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">System Health</h1>
        <p className="mt-1 text-sm text-text-muted">
          Best-effort, short-timeout checks against each real dependency, run fresh on every load of this page -
          never a fabricated green light.
        </p>
      </div>

      <Card>
        <CardHeader title="API" />
        <CardBody>
          {!health.ok ? (
            <ErrorState error={health.error} />
          ) : (
            <div className="flex items-center gap-2 text-sm">
              <Badge variant={health.data.status === "healthy" ? "success" : "danger"}>{health.data.status}</Badge>
              <span className="text-text-muted">{health.data.service}</span>
            </div>
          )}
        </CardBody>
      </Card>

      {!status.ok ? (
        <ErrorState error={status.error} />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {status.data.dependencies.map((dep) => (
            <Card key={dep.name}>
              <CardHeader
                title={titleCase(dep.name)}
                action={dep.available ? <Badge variant="success">Available</Badge> : <Badge variant="danger">Unavailable</Badge>}
              />
              <CardBody className="flex flex-col gap-2 text-sm">
                <p className="text-text-muted">{DEPENDENCY_DESCRIPTIONS[dep.name]}</p>
                {dep.detail ? <p className="text-foreground">{dep.detail}</p> : null}
                <p className="text-xs text-text-muted">Checked {formatDateTime(dep.checked_at)}</p>
              </CardBody>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
