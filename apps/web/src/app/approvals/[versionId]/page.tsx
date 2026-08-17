import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Card, CardBody, CardHeader, ErrorState, StatusPill } from "@/components/ui";
import { ApprovalActionPanel } from "@/components/features/ApprovalActionPanel";
import { ApiError } from "@/lib/api/client";
import { studioApi } from "@/lib/api";
import { formatDateTime } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export async function generateMetadata(props: PageProps<"/approvals/[versionId]">): Promise<Metadata> {
  const { versionId } = await props.params;
  return { title: versionId };
}

async function settle<T>(p: Promise<T>) {
  try {
    return { ok: true as const, data: await p };
  } catch (error) {
    return { ok: false as const, error };
  }
}

export default async function ApprovalDetailPage(props: PageProps<"/approvals/[versionId]">) {
  const { versionId } = await props.params;

  let version;
  try {
    version = await studioApi.getExperimentVersion(versionId);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    return <ErrorState error={error} />;
  }

  const [history, template] = await Promise.all([
    settle(studioApi.getApprovalHistory(versionId)),
    settle(studioApi.getTemplate(version.template_id, version.template_version)),
  ]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-xl font-semibold text-foreground">{version.version_id}</h1>
          <StatusPill status={version.status} />
        </div>
        <p className="mt-1 text-sm text-text-muted">
          <Link href={`/experiments/${version.experiment_id}`} className="text-accent hover:underline">
            {version.experiment_id}
          </Link>{" "}
          · version {version.version_number} · created by {version.created_by} on {formatDateTime(version.created_at)}
        </p>
      </div>

      <div className="rounded-xl border border-warning-bg bg-warning-bg p-4 text-sm text-warning">
        The experiment-version API returns workflow metadata only (domain pack, template, status, who/when) - not the
        full content (title, related CVEs, research question/hypothesis, dataset configuration, metrics). Once this
        version is approved and materialised, the full definition is viewable at{" "}
        <Link href={`/experiments/${version.experiment_id}`} className="underline">
          /experiments/{version.experiment_id}
        </Link>
        .
      </div>

      <Card>
        <CardHeader title="Version" />
        <CardBody className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-3">
          <Field label="Domain pack" value={version.domain_pack_id} />
          <Field label="Template" value={`${version.template_id} v${version.template_version}`} />
          <Field label="Updated" value={formatDateTime(version.updated_at)} />
          {template.ok ? (
            <>
              <Field label="Safety level" value={template.data.safety_level} />
              <Field label="Baseline strategy" value={template.data.allowed_baseline_strategies[0]} mono />
              <Field label="Mitigation strategy" value={template.data.allowed_mitigation_strategies[0]} mono />
            </>
          ) : null}
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Decision" />
        <CardBody>
          <ApprovalActionPanel versionId={versionId} status={version.status} />
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Approval history" />
        <CardBody>
          {!history.ok ? (
            <ErrorState error={history.error} />
          ) : history.data.length === 0 ? (
            <p className="text-sm text-text-muted">No decisions recorded yet.</p>
          ) : (
            <ul className="flex flex-col gap-3">
              {history.data
                .slice()
                .sort((a, b) => b.decided_at.localeCompare(a.decided_at))
                .map((d, i) => (
                  <li key={i} className="rounded-lg border border-border p-3 text-sm">
                    <div className="flex items-center justify-between">
                      <p className="font-medium text-foreground">
                        {d.from_status} → {d.to_status}
                      </p>
                      <span className="text-xs text-text-muted">{formatDateTime(d.decided_at)}</span>
                    </div>
                    <p className="mt-1 text-text-muted">by {d.actor}</p>
                    {d.reason ? <p className="mt-1 text-foreground">{d.reason}</p> : null}
                  </li>
                ))}
            </ul>
          )}
        </CardBody>
      </Card>
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-xs font-medium tracking-wide text-text-muted uppercase">{label}</p>
      <p className={mono ? "mt-0.5 font-mono text-xs text-foreground" : "mt-0.5 text-foreground"}>{value}</p>
    </div>
  );
}
