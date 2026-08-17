import type { Metadata } from "next";
import Link from "next/link";
import { EmptyState, ErrorState, StatusPill } from "@/components/ui";
import { Button } from "@/components/ui/Button";
import { Select } from "@/components/ui/Field";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { jobsApi } from "@/lib/api";
import type { JobStatus } from "@/lib/api/types";
import { formatDateTime, titleCase } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Runs" };

const STATUSES: JobStatus[] = ["queued", "running", "completed", "failed", "denied"];

function firstValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function RunsPage(props: PageProps<"/runs">) {
  const raw = await props.searchParams;
  const status = firstValue(raw.status) as JobStatus | undefined;

  let jobs;
  let error: unknown = null;
  try {
    jobs = (await jobsApi.listJobs({ status, limit: 100 })).jobs;
  } catch (err) {
    error = err;
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Runs</h1>
        <p className="mt-1 text-sm text-text-muted">Most recently submitted validation jobs first.</p>
      </div>

      <form method="GET" action="/runs" className="flex items-end gap-3 rounded-xl border border-border bg-surface p-4">
        <div className="flex flex-col gap-1.5">
          <label htmlFor="status" className="text-sm font-medium text-foreground">
            Status
          </label>
          <Select id="status" name="status" defaultValue={status ?? ""} className="w-48">
            <option value="">All statuses</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {titleCase(s)}
              </option>
            ))}
          </Select>
        </div>
        <Button type="submit" variant="primary">
          Apply
        </Button>
        {status ? (
          <Button href="/runs" variant="ghost">
            Clear
          </Button>
        ) : null}
      </form>

      {error ? (
        <ErrorState error={error} />
      ) : !jobs || jobs.length === 0 ? (
        <EmptyState title="No runs" description={status ? "No runs match this filter." : "No runs have been submitted yet."} />
      ) : (
        <div className="rounded-xl border border-border bg-surface shadow-sm">
          <TableContainer>
            <Table>
              <THead>
                <TR>
                  <TH>Job</TH>
                  <TH>Experiment</TH>
                  <TH>Context</TH>
                  <TH>Status</TH>
                  <TH>Submitted</TH>
                  <TH>Updated</TH>
                </TR>
              </THead>
              <TBody>
                {jobs.map((job) => (
                  <TR key={job.job_id}>
                    <TD>
                      <Link href={`/runs/${job.job_id}`} className="font-medium text-accent hover:underline">
                        {job.job_id}
                      </Link>
                    </TD>
                    <TD>
                      <Link href={`/experiments/${job.experiment_id}`} className="text-accent hover:underline">
                        {job.experiment_id}
                      </Link>
                    </TD>
                    <TD>{titleCase(job.execution_context)}</TD>
                    <TD>
                      <StatusPill status={job.status} />
                    </TD>
                    <TD title={formatDateTime(job.submitted_at)}>{formatDateTime(job.submitted_at)}</TD>
                    <TD title={formatDateTime(job.updated_at)}>{formatDateTime(job.updated_at)}</TD>
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
