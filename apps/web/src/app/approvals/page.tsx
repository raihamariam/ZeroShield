import type { Metadata } from "next";
import Link from "next/link";
import { EmptyState, ErrorState, StatusPill } from "@/components/ui";
import { Button } from "@/components/ui/Button";
import { Input, Select } from "@/components/ui/Field";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { studioApi } from "@/lib/api";
import type { ExperimentVersionResponse, ExperimentVersionStatus } from "@/lib/api/types";
import { formatDateTime } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Approvals" };

const ALL_STATUSES: ExperimentVersionStatus[] = ["draft", "ready_for_review", "under_review", "approved", "rejected", "retired"];
const QUEUE_STATUSES: ExperimentVersionStatus[] = ["ready_for_review", "under_review"];

function firstValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function ApprovalsPage(props: PageProps<"/approvals">) {
  const raw = await props.searchParams;
  const status = firstValue(raw.status) as ExperimentVersionStatus | undefined;
  const experimentId = firstValue(raw.experiment_id);

  let versions: ExperimentVersionResponse[] | undefined;
  let error: unknown = null;
  try {
    if (status) {
      versions = (await studioApi.listExperimentVersions({ status, experiment_id: experimentId })).versions;
    } else {
      const results = await Promise.all(
        QUEUE_STATUSES.map((s) => studioApi.listExperimentVersions({ status: s, experiment_id: experimentId }))
      );
      versions = results.flatMap((r) => r.versions);
    }
    versions.sort((a, b) => b.updated_at.localeCompare(a.updated_at));
  } catch (err) {
    error = err;
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Approvals</h1>
        <p className="mt-1 text-sm text-text-muted">
          {status ? `Showing "${status}" versions.` : "Showing the review queue (ready for review + under review)."}
        </p>
      </div>

      <form method="GET" action="/approvals" className="flex items-end gap-3 rounded-xl border border-border bg-surface p-4">
        <div className="flex flex-col gap-1.5">
          <label htmlFor="status" className="text-sm font-medium text-foreground">
            Status
          </label>
          <Select id="status" name="status" defaultValue={status ?? ""} className="w-48">
            <option value="">Review queue</option>
            {ALL_STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </Select>
        </div>
        <div className="flex flex-col gap-1.5">
          <label htmlFor="experiment_id" className="text-sm font-medium text-foreground">
            Experiment ID
          </label>
          <Input id="experiment_id" name="experiment_id" defaultValue={experimentId ?? ""} className="w-48" />
        </div>
        <Button type="submit" variant="primary">
          Apply
        </Button>
        {status || experimentId ? (
          <Button href="/approvals" variant="ghost">
            Clear
          </Button>
        ) : null}
      </form>

      {error ? (
        <ErrorState error={error} />
      ) : !versions || versions.length === 0 ? (
        <EmptyState title="Nothing here" description="No experiment versions match this view." />
      ) : (
        <div className="rounded-xl border border-border bg-surface shadow-sm">
          <TableContainer>
            <Table>
              <THead>
                <TR>
                  <TH>Version</TH>
                  <TH>Experiment</TH>
                  <TH>Status</TH>
                  <TH>Created by</TH>
                  <TH>Updated</TH>
                </TR>
              </THead>
              <TBody>
                {versions.map((v) => (
                  <TR key={v.version_id}>
                    <TD>
                      <Link href={`/approvals/${v.version_id}`} className="font-medium text-accent hover:underline">
                        {v.version_id}
                      </Link>
                    </TD>
                    <TD>{v.experiment_id}</TD>
                    <TD>
                      <StatusPill status={v.status} />
                    </TD>
                    <TD>{v.created_by}</TD>
                    <TD title={formatDateTime(v.updated_at)}>{formatDateTime(v.updated_at)}</TD>
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
