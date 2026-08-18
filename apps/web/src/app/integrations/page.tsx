import type { Metadata } from "next";
import { Badge, Card, CardBody, CardHeader, EmptyState, ErrorState } from "@/components/ui";
import { TriggerSyncButton } from "@/components/features/TriggerSyncButton";
import { authApi, intelligenceApi } from "@/lib/api";
import { formatDateTime, titleCase } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Integrations" };

async function settle<T>(p: Promise<T>) {
  try {
    return { ok: true as const, data: await p };
  } catch (error) {
    return { ok: false as const, error };
  }
}

export default async function IntegrationsPage() {
  const [sources, syncs, me] = await Promise.all([
    settle(intelligenceApi.listIntegrations()),
    settle(intelligenceApi.listSyncs({ limit: 20 })),
    settle(authApi.me()),
  ]);
  // POST /intelligence/sync requires RESEARCHER or ADMIN server-side (see
  // require_role in zeroshield.api.routes.intelligence.submit_sync) - matching
  // that exactly here (not just "hide for VIEWER") is a UI convenience only,
  // not the enforcement boundary, which stays server-side regardless.
  const canTriggerSync = me.ok && (me.data.role === "researcher" || me.data.role === "admin");

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Integrations</h1>
        <p className="mt-1 text-sm text-text-muted">
          Threat-intelligence source connectors: NVD, CISA KEV, EPSS, and vendor advisories. Reachability is checked
          live on every load of this page - never a cached &quot;green&quot;.
        </p>
      </div>

      {!sources.ok ? (
        <ErrorState error={sources.error} />
      ) : sources.data.sources.length === 0 ? (
        <EmptyState title="No integrations registered" />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {sources.data.sources.map((source) => (
            <Card key={source.source}>
              <CardHeader
                title={titleCase(source.source)}
                action={source.available ? <Badge variant="success">Reachable</Badge> : <Badge variant="danger">Unreachable</Badge>}
              />
              <CardBody className="flex flex-col gap-3 text-sm">
                {source.detail ? <p className="text-text-muted">{source.detail}</p> : null}
                <p className="text-xs text-text-muted">Checked {formatDateTime(source.checked_at)}</p>
                {canTriggerSync ? <TriggerSyncButton source={source.source} /> : null}
              </CardBody>
            </Card>
          ))}
        </div>
      )}

      <div>
        <h2 className="text-base font-semibold text-foreground">Recent syncs</h2>
        {!syncs.ok ? (
          <ErrorState error={syncs.error} className="mt-3" />
        ) : syncs.data.syncs.length === 0 ? (
          <EmptyState title="No syncs yet" className="mt-3" />
        ) : (
          <ul className="mt-3 flex flex-col gap-2">
            {syncs.data.syncs.map((s) => (
              <li key={s.sync_id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border p-3 text-sm">
                <div>
                  <p className="font-medium text-foreground">
                    {titleCase(s.source)} <span className="font-mono text-xs text-text-muted">{s.sync_id}</span>
                  </p>
                  <p className="text-xs text-text-muted">
                    Started {formatDateTime(s.started_at)}
                    {s.completed_at ? ` · Completed ${formatDateTime(s.completed_at)}` : ""}
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-text-muted">
                    +{s.created_count} new · {s.updated_count} updated · {s.unchanged_count} unchanged
                    {s.failed_count > 0 ? ` · ${s.failed_count} failed` : ""}
                  </span>
                  <StatusBadge status={s.status} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const variant = status === "completed" ? "success" : status === "failed" ? "danger" : status === "partial" ? "warning" : "info";
  return <Badge variant={variant}>{titleCase(status)}</Badge>;
}
