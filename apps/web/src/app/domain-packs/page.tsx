import type { Metadata } from "next";
import Link from "next/link";
import { Badge, Card, CardBody, CardHeader, EmptyState, ErrorState, StatusPill } from "@/components/ui";
import { studioApi } from "@/lib/api";
import { formatDomain, titleCase } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Domain Packs" };

export default async function DomainPacksPage() {
  let packsWithTemplates;
  let error: unknown = null;
  try {
    const { domain_packs } = await studioApi.listDomainPacks();
    packsWithTemplates = await Promise.all(
      domain_packs.map(async (pack) => ({
        pack,
        templates: await studioApi.listDomainPackTemplates(pack.pack_id).then((r) => r.templates),
      }))
    );
  } catch (err) {
    error = err;
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Domain Packs</h1>
        <p className="mt-1 text-sm text-text-muted">
          What ZeroShield can validate: each domain pack declares its supported failure patterns, allow-listed
          strategies, dataset generator, and the validation templates built on top of it.
        </p>
      </div>

      {error ? (
        <ErrorState error={error} />
      ) : !packsWithTemplates || packsWithTemplates.length === 0 ? (
        <EmptyState title="No domain packs registered" />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {packsWithTemplates.map(({ pack, templates }) => (
            <Card key={pack.pack_id}>
              <CardHeader
                title={pack.name}
                description={`${pack.pack_id} · v${pack.version}`}
                action={<Badge variant="neutral">{formatDomain(pack.domain)}</Badge>}
              />
              <CardBody className="flex flex-col gap-4 text-sm">
                <div>
                  <p className="mb-1 font-medium text-foreground">Supported failure patterns</p>
                  <div className="flex flex-wrap gap-1.5">
                    {pack.supported_failure_patterns.map((p) => (
                      <Badge key={p} variant="neutral">
                        {p}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="mb-1 font-medium text-foreground">Allowed strategies</p>
                  <div className="flex flex-wrap gap-1.5">
                    {pack.allowed_strategy_ids.map((s) => (
                      <Badge key={s} variant="info">
                        {s}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <p className="text-xs font-medium tracking-wide text-text-muted uppercase">Dataset generator</p>
                    <p className="mt-0.5 font-mono text-xs text-foreground">{pack.dataset_generator_id}</p>
                  </div>
                  <div>
                    <p className="text-xs font-medium tracking-wide text-text-muted uppercase">Min core version</p>
                    <p className="mt-0.5 text-foreground">{pack.compatibility.min_core_version ?? "—"}</p>
                  </div>
                </div>
                <div>
                  <p className="mb-1 font-medium text-foreground">Metrics collected</p>
                  <div className="flex flex-wrap gap-1.5">
                    {pack.domain_metrics.map((m) => (
                      <Badge key={m} variant="neutral">
                        {titleCase(m)}
                      </Badge>
                    ))}
                  </div>
                </div>

                <div className="border-t border-border pt-3">
                  <p className="mb-2 font-medium text-foreground">Validation templates</p>
                  <ul className="flex flex-col gap-2">
                    {templates.map((t) => (
                      <li key={`${t.template_id}@${t.version}`} className="rounded-lg border border-border p-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <p className="font-medium text-foreground">
                            {t.name} <span className="font-mono text-xs text-text-muted">v{t.version}</span>
                          </p>
                          <StatusPill status={t.safety_level} />
                        </div>
                        <p className="mt-1 text-xs text-text-muted">
                          Baseline: <span className="font-mono">{t.allowed_baseline_strategies.join(", ")}</span> ·
                          Mitigation: <span className="font-mono">{t.allowed_mitigation_strategies.join(", ")}</span>
                        </p>
                        <div className="mt-2">
                          <Link
                            href={`/experiment-studio?domain_pack=${pack.pack_id}&template=${t.template_id}`}
                            className="text-xs font-medium text-accent hover:underline"
                          >
                            Use in Experiment Studio →
                          </Link>
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              </CardBody>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
