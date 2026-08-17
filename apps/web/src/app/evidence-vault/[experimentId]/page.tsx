import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Badge, Card, CardBody, CardHeader, ErrorState } from "@/components/ui";
import { ApiError } from "@/lib/api/client";
import { evidenceApi } from "@/lib/api";
import type { RunEvidenceSummary } from "@/lib/api/types";
import { evidenceBundleUrl } from "@/lib/api/evidence";
import { formatDateTime, titleCase } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export async function generateMetadata(props: PageProps<"/evidence-vault/[experimentId]">): Promise<Metadata> {
  const { experimentId } = await props.params;
  return { title: `Evidence · ${experimentId}` };
}

export default async function EvidenceVaultDetailPage(props: PageProps<"/evidence-vault/[experimentId]">) {
  const { experimentId } = await props.params;

  let evidence;
  try {
    evidence = await evidenceApi.getEvidence(experimentId);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    return <ErrorState error={error} />;
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Evidence · {evidence.experiment_id}</h1>
          <p className="mt-1 font-mono text-xs text-text-muted">{evidence.evidence_location}</p>
        </div>
        <a
          href={evidenceBundleUrl(experimentId)}
          className="inline-flex items-center rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-accent-foreground hover:opacity-90"
        >
          Download evidence bundle (.zip)
        </a>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <RunCard label="Baseline" run={evidence.baseline} />
        <RunCard label="Mitigation" run={evidence.mitigation} />
      </div>

      <p className="text-xs text-text-muted">
        Individual artifact filenames aren&apos;t listed by this API - download the bundle above to inspect
        manifest.json and artefacts directly. Integrity is verified live against the manifest&apos;s own hash on
        every load of this page, not a one-time check.
      </p>

      <Link href={`/experiments/${experimentId}`} className="text-sm font-medium text-accent hover:underline">
        ← Back to experiment
      </Link>
    </div>
  );
}

function RunCard({ label, run }: { label: string; run: RunEvidenceSummary }) {
  return (
    <Card>
      <CardHeader
        title={label}
        description={run.run_id}
        action={run.integrity_verified ? <Badge variant="success">Integrity verified</Badge> : <Badge variant="danger">Integrity check FAILED</Badge>}
      />
      <CardBody className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
        <Field label="Strategy" value={run.strategy_id} mono />
        <Field label="Started" value={formatDateTime(run.started_at)} />
        <Field label="Completed" value={formatDateTime(run.completed_at)} />
        <Field label="Dataset ID" value={run.dataset_id} mono />
        <Field label="Dataset SHA-256" value={run.dataset_sha256} mono />
        <Field label="Git commit" value={run.git_commit} mono />
        <Field label="Manifest SHA-256" value={run.manifest_sha256} mono />
        <Field label="Mode" value={titleCase(run.mode)} />
      </CardBody>
    </Card>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <p className="text-xs font-medium tracking-wide text-text-muted uppercase">{label}</p>
      <p className={mono ? "mt-0.5 truncate font-mono text-xs text-foreground" : "mt-0.5 text-foreground"} title={mono ? value : undefined}>
        {value}
      </p>
    </div>
  );
}
