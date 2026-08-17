import type { Metadata } from "next";
import Link from "next/link";
import { Badge, EmptyState, ErrorState, StatusPill } from "@/components/ui";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Field";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { experimentsApi } from "@/lib/api";
import { formatDomain, titleCase } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Experiments" };

function firstValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function ExperimentsPage(props: PageProps<"/experiments">) {
  const raw = await props.searchParams;
  const q = (firstValue(raw.q) ?? "").trim().toLowerCase();

  let experiments;
  let error: unknown = null;
  try {
    experiments = (await experimentsApi.listExperiments()).experiments;
  } catch (err) {
    error = err;
  }

  const filtered = experiments
    ? experiments.filter(
        (e) =>
          !q ||
          e.experiment_id.toLowerCase().includes(q) ||
          e.title.toLowerCase().includes(q) ||
          e.domain.toLowerCase().includes(q)
      )
    : experiments;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Experiments</h1>
          <p className="mt-1 text-sm text-text-muted">
            Approved and legacy experiments discovered on disk. Drafts and versions awaiting review live in{" "}
            <Link href="/approvals" className="text-accent hover:underline">
              Approvals
            </Link>
            .
          </p>
        </div>
        <Button href="/experiment-studio" variant="primary">
          New experiment
        </Button>
      </div>

      <form method="GET" action="/experiments" className="flex items-end gap-3 rounded-xl border border-border bg-surface p-4">
        <div className="flex flex-col gap-1.5">
          <label htmlFor="q" className="text-sm font-medium text-foreground">
            Search
          </label>
          <Input id="q" name="q" defaultValue={q} placeholder="Experiment ID, title, or domain" className="w-64" />
        </div>
        <Button type="submit" variant="primary">
          Search
        </Button>
        {q ? (
          <Button href="/experiments" variant="ghost">
            Clear
          </Button>
        ) : null}
      </form>

      {error ? (
        <ErrorState error={error} />
      ) : !filtered || filtered.length === 0 ? (
        <EmptyState title="No experiments found" description={q ? "Try a different search." : "No experiments have been discovered yet."} />
      ) : (
        <div className="rounded-xl border border-border bg-surface shadow-sm">
          <TableContainer>
            <Table>
              <THead>
                <TR>
                  <TH>Experiment</TH>
                  <TH>Domain</TH>
                  <TH>Safety level</TH>
                  <TH>Approval status</TH>
                </TR>
              </THead>
              <TBody>
                {filtered.map((e) => (
                  <TR key={e.experiment_id}>
                    <TD>
                      <Link href={`/experiments/${e.experiment_id}`} className="font-medium text-accent hover:underline">
                        {e.experiment_id}
                      </Link>
                      <p className="text-xs text-text-muted">{e.title}</p>
                    </TD>
                    <TD>
                      <Badge variant="neutral">{formatDomain(e.domain)}</Badge>
                    </TD>
                    <TD>{titleCase(e.safety_level)}</TD>
                    <TD>
                      <StatusPill status={e.approval_status} />
                    </TD>
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
