import type { Metadata } from "next";
import Link from "next/link";
import { Badge, EmptyState, ErrorState } from "@/components/ui";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { evidenceApi, experimentsApi } from "@/lib/api";
import { ApiError } from "@/lib/api/client";
import { formatDateTime, formatDomain } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Evidence Vault" };

export default async function EvidenceVaultPage() {
  let experiments;
  let error: unknown = null;
  try {
    experiments = (await experimentsApi.listExperiments()).experiments;
  } catch (err) {
    error = err;
  }

  const rows = experiments
    ? await Promise.all(
        experiments.map(async (e) => {
          try {
            const evidence = await evidenceApi.getEvidence(e.experiment_id);
            return { experiment: e, hasEvidence: true as const, completedAt: evidence.mitigation.completed_at };
          } catch (err) {
            if (err instanceof ApiError && err.status === 404) {
              return { experiment: e, hasEvidence: false as const, completedAt: null };
            }
            return { experiment: e, hasEvidence: false as const, completedAt: null };
          }
        })
      )
    : undefined;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Evidence Vault</h1>
        <p className="mt-1 text-sm text-text-muted">
          Provenance for every experiment&apos;s latest run: dataset hash, Git commit, manifest integrity, and the
          downloadable evidence bundle.
        </p>
      </div>

      {error ? (
        <ErrorState error={error} />
      ) : !rows || rows.length === 0 ? (
        <EmptyState title="No experiments" />
      ) : (
        <div className="rounded-xl border border-border bg-surface shadow-sm">
          <TableContainer>
            <Table>
              <THead>
                <TR>
                  <TH>Experiment</TH>
                  <TH>Domain</TH>
                  <TH>Evidence</TH>
                  <TH>Latest run completed</TH>
                </TR>
              </THead>
              <TBody>
                {rows.map(({ experiment, hasEvidence, completedAt }) => (
                  <TR key={experiment.experiment_id}>
                    <TD>
                      {hasEvidence ? (
                        <Link href={`/evidence-vault/${experiment.experiment_id}`} className="font-medium text-accent hover:underline">
                          {experiment.experiment_id}
                        </Link>
                      ) : (
                        <span className="font-medium text-foreground">{experiment.experiment_id}</span>
                      )}
                      <p className="text-xs text-text-muted">{experiment.title}</p>
                    </TD>
                    <TD>{formatDomain(experiment.domain)}</TD>
                    <TD>
                      {hasEvidence ? <Badge variant="success">Available</Badge> : <Badge variant="neutral">No runs yet</Badge>}
                    </TD>
                    <TD>{completedAt ? formatDateTime(completedAt) : "—"}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </TableContainer>
        </div>
      )}
    </div>
  );
}
