import type { Metadata } from "next";
import Link from "next/link";
import { RevalidationDecisionButtons } from "@/components/features/RevalidationDecisionButtons";
import { RevalidationScanButton } from "@/components/features/RevalidationScanButton";
import { EmptyState, ErrorState, StatusPill } from "@/components/ui";
import { Select } from "@/components/ui/Field";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { revalidationApi } from "@/lib/api";
import { formatDateTime, titleCase } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Revalidation Queue" };

function firstValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function RevalidationPage(props: PageProps<"/revalidation">) {
  const raw = await props.searchParams;
  const status = firstValue(raw.status) ?? "pending";

  let candidates;
  let error: unknown = null;
  try {
    candidates = (await revalidationApi.listRevalidationCandidates({ status: status || undefined })).candidates;
  } catch (err) {
    error = err;
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Revalidation Queue</h1>
          <p className="mt-1 text-sm text-text-muted">
            Deterministic triggers only (KEV/EPSS change, advisory update, new control version, staleness, a newly
            correlated CVE). Approving here never executes a run - it only unlocks submitting one the normal way.
          </p>
        </div>
        <RevalidationScanButton />
      </div>

      <form method="GET" action="/revalidation" className="flex max-w-xs items-end gap-2">
        <div className="flex-1">
          <label htmlFor="status" className="mb-1.5 block text-sm font-medium text-foreground">
            Status
          </label>
          <Select id="status" name="status" defaultValue={status}>
            <option value="pending">Pending</option>
            <option value="approved">Approved</option>
            <option value="dismissed">Dismissed</option>
            <option value="">All</option>
          </Select>
        </div>
        <button type="submit" className="rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-accent-foreground hover:opacity-90">
          Filter
        </button>
      </form>

      {error ? (
        <ErrorState error={error} />
      ) : !candidates || candidates.length === 0 ? (
        <EmptyState
          title="Nothing here"
          description="Run a scan to check for new triggers, or adjust the status filter."
        />
      ) : (
        <TableContainer>
          <Table>
            <THead>
              <TR>
                <TH>Control</TH>
                <TH>Trigger</TH>
                <TH>Detail</TH>
                <TH>Status</TH>
                <TH>Raised</TH>
                <TH>Reviewed by</TH>
                <TH></TH>
              </TR>
            </THead>
            <TBody>
              {candidates.map((c) => (
                <TR key={c.candidate_id}>
                  <TD>
                    <Link href={`/controls/${c.control_id}`} className="font-medium text-accent hover:underline">
                      {c.control_id}
                    </Link>
                  </TD>
                  <TD>{titleCase(c.trigger_type)}</TD>
                  <TD className="max-w-sm truncate" title={c.trigger_detail}>
                    {c.trigger_detail}
                  </TD>
                  <TD>
                    <StatusPill status={c.status} />
                  </TD>
                  <TD title={formatDateTime(c.created_at)}>{formatDateTime(c.created_at)}</TD>
                  <TD>{c.reviewed_by ?? "—"}</TD>
                  <TD>{c.status === "pending" ? <RevalidationDecisionButtons candidateId={c.candidate_id} /> : null}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </TableContainer>
      )}
    </div>
  );
}
