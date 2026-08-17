import type { Metadata } from "next";
import Link from "next/link";
import { EmptyState, ErrorState, Pagination, StatusPill } from "@/components/ui";
import { Button } from "@/components/ui/Button";
import { FormField, Input, Select } from "@/components/ui/Field";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { intelligenceApi } from "@/lib/api";
import type { PriorityQueueParams } from "@/lib/api/intelligence";
import { formatDateTime, formatDomain, formatNumber } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Priority Queue" };

const PAGE_SIZE = 25;

function firstValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function parseFloatParam(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const n = Number.parseFloat(value);
  return Number.isFinite(n) ? n : undefined;
}

function parseIntParam(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : undefined;
}

export default async function PriorityQueuePage(props: PageProps<"/priority-queue">) {
  const raw = await props.searchParams;
  const domain = firstValue(raw.domain) as PriorityQueueParams["domain"];
  const supportStatus = firstValue(raw.support_status) as PriorityQueueParams["support_status"];
  const priorityGte = parseFloatParam(firstValue(raw.priority_gte));
  const offset = parseIntParam(firstValue(raw.offset)) ?? 0;

  const hasActiveFilters = Boolean(domain || supportStatus || priorityGte !== undefined);

  let queue;
  let queueError: unknown = null;
  try {
    queue = await intelligenceApi.getPriorityQueue({
      domain,
      support_status: supportStatus,
      priority_gte: priorityGte,
      limit: PAGE_SIZE,
      offset,
    });
  } catch (error) {
    queueError = error;
  }

  const searchParamsForPagination: Record<string, string | undefined> = {
    domain,
    support_status: supportStatus,
    priority_gte: priorityGte?.toString(),
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Priority Queue</h1>
        <p className="mt-1 text-sm text-text-muted">
          Validation candidates ZeroShield can actually test, ranked most-worth-validating first. Only CVEs in a
          supported or partially-supported domain ever appear here.
        </p>
      </div>

      <form
        method="GET"
        action="/priority-queue"
        className="grid grid-cols-1 gap-3 rounded-xl border border-border bg-surface p-4 sm:grid-cols-2 lg:grid-cols-4"
      >
        <FormField id="domain" label="Domain">
          <Select id="domain" name="domain" defaultValue={domain ?? ""}>
            <option value="">All domains</option>
            <option value="VPN">VPN</option>
            <option value="TELECOM">Telecom</option>
          </Select>
        </FormField>
        <FormField id="support_status" label="Support status">
          <Select id="support_status" name="support_status" defaultValue={supportStatus ?? ""}>
            <option value="">Any</option>
            <option value="supported">Supported</option>
            <option value="partially_supported">Partially supported</option>
          </Select>
        </FormField>
        <FormField id="priority_gte" label="Priority score ≥">
          <Input id="priority_gte" name="priority_gte" type="number" min={0} max={100} step={1} defaultValue={priorityGte ?? ""} />
        </FormField>
        <div className="flex items-end gap-2">
          <Button type="submit" variant="primary">
            Apply filters
          </Button>
          {hasActiveFilters ? (
            <Button href="/priority-queue" variant="ghost">
              Clear filters
            </Button>
          ) : null}
        </div>
      </form>

      {queueError ? (
        <ErrorState error={queueError} />
      ) : !queue || queue.candidates.length === 0 ? (
        <EmptyState
          title="No priority candidates"
          description={hasActiveFilters ? "Try widening or clearing your filters." : "The priority queue is currently empty."}
        />
      ) : (
        <div className="rounded-xl border border-border bg-surface shadow-sm">
          <TableContainer>
            <Table>
              <THead>
                <TR>
                  <TH>CVE</TH>
                  <TH>Domain</TH>
                  <TH>Priority</TH>
                  <TH>Support</TH>
                  <TH>Why</TH>
                  <TH>Linked experiments</TH>
                  <TH>Generated</TH>
                </TR>
              </THead>
              <TBody>
                {queue.candidates.map((c) => (
                  <TR key={c.cve_id}>
                    <TD>
                      <Link href={`/vulnerabilities/${c.cve_id}`} className="font-medium text-accent hover:underline">
                        {c.cve_id}
                      </Link>
                    </TD>
                    <TD>{c.domain ? formatDomain(c.domain) : "—"}</TD>
                    <TD>
                      <div className="flex items-center gap-2">
                        <StatusPill status={c.priority_label} />
                        <span className="text-text-muted">{formatNumber(c.priority_score, 1)}</span>
                      </div>
                    </TD>
                    <TD>
                      <StatusPill status={c.support_status} />
                    </TD>
                    <TD className="max-w-xs truncate" title={c.explanation.join("; ") || undefined}>
                      {c.explanation.join("; ") || "—"}
                    </TD>
                    <TD>
                      {c.existing_experiment_ids.length === 0 ? (
                        "—"
                      ) : (
                        <div className="flex flex-wrap gap-x-1.5">
                          {c.existing_experiment_ids.map((id, i) => (
                            <span key={id}>
                              <Link href={`/experiments/${id}`} className="text-accent hover:underline">
                                {id}
                              </Link>
                              {i < c.existing_experiment_ids.length - 1 ? "," : ""}
                            </span>
                          ))}
                        </div>
                      )}
                    </TD>
                    <TD title={formatDateTime(c.generated_at)}>{formatDateTime(c.generated_at)}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </TableContainer>
          <Pagination
            total={queue.total}
            limit={queue.limit}
            offset={queue.offset}
            basePath="/priority-queue"
            searchParams={searchParamsForPagination}
          />
        </div>
      )}
    </div>
  );
}
