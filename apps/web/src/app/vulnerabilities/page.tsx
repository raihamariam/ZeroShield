import type { Metadata } from "next";
import Link from "next/link";
import { Badge, EmptyState, ErrorState, Pagination, StatusPill } from "@/components/ui";
import { Button } from "@/components/ui/Button";
import { FormField, Input, Select } from "@/components/ui/Field";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { CveJumpForm } from "@/components/features/CveJumpForm";
import { intelligenceApi } from "@/lib/api";
import type { VulnerabilityListParams } from "@/lib/api/intelligence";
import { buildPriorityMap } from "@/lib/priority";
import { formatDateTime, formatDomain, formatNumber, formatPercent } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Vulnerabilities" };

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

export default async function VulnerabilitiesPage(props: PageProps<"/vulnerabilities">) {
  const raw = await props.searchParams;
  const domain = firstValue(raw.domain) as VulnerabilityListParams["domain"];
  const vendor = firstValue(raw.vendor);
  const product = firstValue(raw.product);
  const kev = firstValue(raw.kev) === "true";
  const cvssGte = parseFloatParam(firstValue(raw.cvss_gte));
  const epssGte = parseFloatParam(firstValue(raw.epss_gte));
  const offset = parseIntParam(firstValue(raw.offset)) ?? 0;

  const hasActiveFilters = Boolean(domain || vendor || product || kev || cvssGte !== undefined || epssGte !== undefined);

  const listParams: VulnerabilityListParams = {
    domain,
    vendor: vendor || undefined,
    product: product || undefined,
    kev: kev || undefined,
    cvss_gte: cvssGte,
    epss_gte: epssGte,
    limit: PAGE_SIZE,
    offset,
  };

  let list;
  let listError: unknown = null;
  try {
    list = await intelligenceApi.listVulnerabilities(listParams);
  } catch (error) {
    listError = error;
  }

  const priorityMap = list
    ? await buildPriorityMap(list.vulnerabilities.map((v) => (v.domain_guess as "VPN" | "TELECOM" | null) ?? null))
    : new Map();

  const searchParamsForPagination: Record<string, string | undefined> = {
    domain,
    vendor,
    product,
    kev: kev ? "true" : undefined,
    cvss_gte: cvssGte?.toString(),
    epss_gte: epssGte?.toString(),
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Vulnerabilities</h1>
          <p className="mt-1 text-sm text-text-muted">
            The merged threat-intelligence system of record - every ingested CVE, regardless of whether ZeroShield
            can validate it. Sorted by most recently updated.
          </p>
        </div>
        <CveJumpForm />
      </div>

      <form method="GET" action="/vulnerabilities" className="grid grid-cols-1 gap-3 rounded-xl border border-border bg-surface p-4 sm:grid-cols-2 lg:grid-cols-6">
        <FormField id="domain" label="Domain">
          <Select id="domain" name="domain" defaultValue={domain ?? ""}>
            <option value="">All domains</option>
            <option value="VPN">VPN</option>
            <option value="TELECOM">Telecom</option>
          </Select>
        </FormField>
        <FormField id="vendor" label="Vendor">
          <Input id="vendor" name="vendor" defaultValue={vendor ?? ""} placeholder="e.g. Cisco" />
        </FormField>
        <FormField id="product" label="Product">
          <Input id="product" name="product" defaultValue={product ?? ""} placeholder="e.g. AnyConnect" />
        </FormField>
        <FormField id="cvss_gte" label="CVSS ≥">
          <Input id="cvss_gte" name="cvss_gte" type="number" min={0} max={10} step={0.1} defaultValue={cvssGte ?? ""} />
        </FormField>
        <FormField id="epss_gte" label="EPSS ≥">
          <Input id="epss_gte" name="epss_gte" type="number" min={0} max={1} step={0.01} defaultValue={epssGte ?? ""} />
        </FormField>
        <div className="flex flex-col justify-end gap-1.5">
          <label className="flex items-center gap-2 text-sm font-medium text-foreground">
            <input
              type="checkbox"
              name="kev"
              value="true"
              defaultChecked={kev}
              className="h-4 w-4 rounded border-border text-accent focus-visible:outline-2 focus-visible:outline-focus-ring"
            />
            KEV listed only
          </label>
        </div>
        <div className="flex items-end gap-2 sm:col-span-2 lg:col-span-6">
          <Button type="submit" variant="primary">
            Apply filters
          </Button>
          {hasActiveFilters ? (
            <Button href="/vulnerabilities" variant="ghost">
              Clear filters
            </Button>
          ) : null}
        </div>
      </form>

      {listError ? (
        <ErrorState error={listError} />
      ) : !list || list.vulnerabilities.length === 0 ? (
        <EmptyState
          title="No vulnerabilities match these filters"
          description={hasActiveFilters ? "Try widening or clearing your filters." : "No vulnerabilities have been ingested yet."}
        />
      ) : (
        <div className="rounded-xl border border-border bg-surface shadow-sm">
          <TableContainer>
            <Table>
              <THead>
                <TR>
                  <TH>CVE</TH>
                  <TH>Vendor</TH>
                  <TH>CVSS</TH>
                  <TH>EPSS</TH>
                  <TH>KEV</TH>
                  <TH>ZeroShield priority</TH>
                  <TH>Domain</TH>
                  <TH>Support</TH>
                  <TH>Last updated</TH>
                </TR>
              </THead>
              <TBody>
                {list.vulnerabilities.map((v) => {
                  const candidate = priorityMap.get(v.cve_id);
                  return (
                    <TR key={v.cve_id}>
                      <TD>
                        <Link href={`/vulnerabilities/${v.cve_id}`} className="font-medium text-accent hover:underline">
                          {v.cve_id}
                        </Link>
                      </TD>
                      <TD>{v.vendor ?? "—"}</TD>
                      <TD>{formatNumber(v.cvss_score, 1)}</TD>
                      <TD>{formatPercent(v.epss_score)}</TD>
                      <TD>{v.kev_listed ? <Badge variant="danger">KEV</Badge> : "—"}</TD>
                      <TD>{candidate ? <StatusPill status={candidate.priority_label} /> : "—"}</TD>
                      <TD>{v.domain_guess ? formatDomain(v.domain_guess) : "—"}</TD>
                      <TD>{candidate ? <StatusPill status={candidate.support_status} /> : "—"}</TD>
                      <TD title={formatDateTime(v.last_updated_at)}>{formatDateTime(v.last_updated_at)}</TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          </TableContainer>
          <Pagination
            total={list.total}
            limit={list.limit}
            offset={list.offset}
            basePath="/vulnerabilities"
            searchParams={searchParamsForPagination}
          />
        </div>
      )}
    </div>
  );
}
