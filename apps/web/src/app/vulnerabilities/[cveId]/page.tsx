import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { AnalystActionsPanel } from "@/components/features/AnalystActionsPanel";
import { Badge, Card, CardBody, CardHeader, EmptyState, ErrorState, StatusPill } from "@/components/ui";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { ApiError } from "@/lib/api/client";
import { analystApi, assetsApi, intelligenceApi } from "@/lib/api";
import { buildPriorityMap } from "@/lib/priority";
import { formatDateTime, formatDomain, formatNumber, formatPercent, titleCase } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export async function generateMetadata(props: PageProps<"/vulnerabilities/[cveId]">): Promise<Metadata> {
  const { cveId } = await props.params;
  return { title: cveId };
}

export default async function VulnerabilityDetailPage(props: PageProps<"/vulnerabilities/[cveId]">) {
  const { cveId } = await props.params;

  let vulnerability;
  try {
    vulnerability = await intelligenceApi.getVulnerability(cveId);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    return <ErrorState error={error} />;
  }

  const domainPackId = vulnerability.domain_guess ? vulnerability.domain_guess.toLowerCase() : null;

  const [historyResult, priorityMap, correlationsResult, assessmentsResult, affectedAssetsResult] = await Promise.all([
    intelligenceApi.getVulnerabilityHistory(cveId).then(
      (data) => ({ ok: true as const, data }),
      (error: unknown) => ({ ok: false as const, error })
    ),
    buildPriorityMap([(vulnerability.domain_guess as "VPN" | "TELECOM" | null) ?? null]),
    analystApi.getCorrelations(cveId).then(
      (data) => ({ ok: true as const, data }),
      (error: unknown) => ({ ok: false as const, error })
    ),
    analystApi.listAssessments({ subject_id: cveId }).then(
      (data) => ({ ok: true as const, data }),
      (error: unknown) => ({ ok: false as const, error })
    ),
    assetsApi.getAffectedAssets(cveId).then(
      (data) => ({ ok: true as const, data }),
      (error: unknown) => ({ ok: false as const, error })
    ),
  ]);

  const candidate = priorityMap.get(cveId);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-semibold text-foreground">{vulnerability.cve_id}</h1>
            {vulnerability.kev_listed ? <Badge variant="danger">KEV</Badge> : null}
            {candidate ? <StatusPill status={candidate.priority_label} /> : null}
            {vulnerability.domain_guess ? <Badge variant="neutral">{formatDomain(vulnerability.domain_guess)}</Badge> : null}
          </div>
          <p className="mt-1 text-sm text-text-muted">
            {vulnerability.vendor ? `${vulnerability.vendor} · ` : ""}
            Last updated {formatDateTime(vulnerability.last_updated_at)} · Sources:{" "}
            {vulnerability.sources.map((s) => titleCase(s)).join(", ") || "—"}
          </p>
        </div>
        {vulnerability.domain_guess ? (
          <Link
            href={`/experiment-studio?cve=${vulnerability.cve_id}`}
            className="inline-flex shrink-0 items-center rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-accent-foreground hover:opacity-90"
          >
            Validate this CVE
          </Link>
        ) : null}
      </div>

      <Card>
        <CardHeader title="Description" />
        <CardBody>
          <p className="text-sm whitespace-pre-wrap text-foreground">{vulnerability.description ?? "No description available."}</p>
        </CardBody>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Scores" />
          <CardBody className="grid grid-cols-2 gap-4 text-sm">
            <ScoreStat label="CVSS score" value={formatNumber(vulnerability.cvss_score, 1)} />
            <ScoreStat label="CVSS version" value={vulnerability.cvss_version ?? "—"} />
            <ScoreStat label="CVSS vector" value={vulnerability.cvss_vector ?? "—"} mono />
            <ScoreStat label="EPSS score" value={formatPercent(vulnerability.epss_score)} />
            <ScoreStat label="EPSS percentile" value={formatPercent(vulnerability.epss_percentile)} />
            <ScoreStat label="Published" value={formatDateTime(vulnerability.published_at)} />
            <ScoreStat label="Last modified" value={formatDateTime(vulnerability.last_modified_at)} />
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="CISA KEV" description="Known Exploited Vulnerabilities catalog" />
          <CardBody className="grid grid-cols-2 gap-4 text-sm">
            <ScoreStat label="Listed" value={vulnerability.kev_listed ? "Yes" : "No"} />
            <ScoreStat label="Date added" value={vulnerability.kev_date_added ? formatDateTime(vulnerability.kev_date_added) : "—"} />
            <ScoreStat label="Remediation due" value={vulnerability.kev_due_date ? formatDateTime(vulnerability.kev_due_date) : "—"} />
            <ScoreStat label="CWE IDs" value={vulnerability.cwe_ids.length > 0 ? vulnerability.cwe_ids.join(", ") : "—"} />
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Priority explanation" description="Why ZeroShield ranks this the way it does" />
          <CardBody>
            {candidate ? (
              <div className="flex flex-col gap-3 text-sm">
                <div className="flex items-center gap-3">
                  <StatusPill status={candidate.priority_label} />
                  <span className="text-text-muted">Score {formatNumber(candidate.priority_score, 1)} / 100</span>
                </div>
                {candidate.explanation.length > 0 ? (
                  <ul className="list-disc space-y-1 pl-5 text-foreground">
                    {candidate.explanation.map((reason, i) => (
                      <li key={i}>{reason}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-text-muted">No explanation reasons were recorded.</p>
                )}
                <p className="text-xs text-text-muted">Generated {formatDateTime(candidate.generated_at)}</p>
              </div>
            ) : vulnerability.domain_guess ? (
              <p className="text-sm text-text-muted">
                Not currently in the priority queue for its domain (either unranked yet, or ranked outside the top
                200 candidates ZeroShield keeps per domain).
              </p>
            ) : (
              <p className="text-sm text-text-muted">
                Not eligible for validation - ZeroShield could not determine a supported domain for this CVE.
              </p>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Validation support" description="Can ZeroShield actually test this?" />
          <CardBody className="flex flex-col gap-3 text-sm">
            {candidate ? (
              <div className="flex items-center gap-2">
                <StatusPill status={candidate.support_status} />
              </div>
            ) : (
              <p className="text-text-muted">
                {vulnerability.domain_guess
                  ? "Support status unavailable (not found in the priority queue - see Priority explanation)."
                  : "Unsupported domain - never appears in the priority queue."}
              </p>
            )}
            <div>
              <p className="mb-1 font-medium text-foreground">Linked experiments</p>
              {candidate && candidate.existing_experiment_ids.length > 0 ? (
                <ul className="flex flex-col gap-1">
                  {candidate.existing_experiment_ids.map((id) => (
                    <li key={id}>
                      <Link href={`/experiments/${id}`} className="text-accent hover:underline">
                        {id}
                      </Link>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-text-muted">No experiment currently validates this CVE.</p>
              )}
            </div>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader
          title="ZeroShield Analyst"
          description="Advisory only - every result is stored unreviewed until a human explicitly reviews it. AI can never approve, execute, or alter evidence."
        />
        <CardBody>
          <AnalystActionsPanel
            cveId={vulnerability.cve_id}
            domainPackId={domainPackId}
            initialAssessments={assessmentsResult.ok ? assessmentsResult.data.assessments : []}
          />
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="CVE clusters" description="Deterministic correlation - never AI, never proof of identical root cause" />
        <CardBody className="p-0">
          {!correlationsResult.ok ? (
            <div className="p-4">
              <ErrorState error={correlationsResult.error} />
            </div>
          ) : correlationsResult.data.correlations.length === 0 ? (
            <div className="p-4">
              <p className="text-sm text-text-muted">No correlated CVEs found above the similarity threshold.</p>
            </div>
          ) : (
            <>
              <TableContainer>
                <Table>
                  <THead>
                    <TR>
                      <TH>CVE</TH>
                      <TH>Score</TH>
                      <TH>Why</TH>
                      <TH>Shared experiments</TH>
                    </TR>
                  </THead>
                  <TBody>
                    {correlationsResult.data.correlations.map((c) => (
                      <TR key={c.cve_id}>
                        <TD>
                          <Link href={`/vulnerabilities/${c.cve_id}`} className="font-medium text-accent hover:underline">
                            {c.cve_id}
                          </Link>
                        </TD>
                        <TD>{formatNumber(c.score, 0)}</TD>
                        <TD className="max-w-sm truncate" title={c.explanation.join("; ")}>
                          {c.explanation.join("; ")}
                        </TD>
                        <TD>{c.shared_experiment_ids.length > 0 ? c.shared_experiment_ids.join(", ") : "—"}</TD>
                      </TR>
                    ))}
                  </TBody>
                </Table>
              </TableContainer>
              <p className="border-t border-border p-3 text-xs text-text-muted">{correlationsResult.data.caveat}</p>
            </>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Potentially affected assets" description="Deterministic vendor/product match against the asset inventory" />
        <CardBody className="p-0">
          {!affectedAssetsResult.ok ? (
            <div className="p-4">
              <ErrorState error={affectedAssetsResult.error} />
            </div>
          ) : affectedAssetsResult.data.assets.length === 0 ? (
            <div className="p-4">
              <p className="text-sm text-text-muted">No inventoried assets match this CVE&apos;s vendor/product.</p>
            </div>
          ) : (
            <TableContainer>
              <Table>
                <THead>
                  <TR>
                    <TH>Asset</TH>
                    <TH>Vendor / product</TH>
                    <TH>Environment</TH>
                    <TH>Exposure</TH>
                    <TH>Criticality</TH>
                  </TR>
                </THead>
                <TBody>
                  {affectedAssetsResult.data.assets.map((asset) => (
                    <TR key={asset.asset_id}>
                      <TD>
                        <Link href={`/assets/${asset.asset_id}`} className="font-medium text-accent hover:underline">
                          {asset.name}
                        </Link>
                      </TD>
                      <TD>
                        {asset.vendor} / {asset.product}
                        {asset.version ? ` (${asset.version})` : ""}
                      </TD>
                      <TD>{titleCase(asset.environment)}</TD>
                      <TD>{titleCase(asset.exposure)}</TD>
                      <TD>{titleCase(asset.criticality)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </TableContainer>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Affected products" />
        <CardBody>
          <EmptyState
            title="Not yet available"
            description="The ZeroShield API does not currently expose per-CVE affected-product data, even though it filters vulnerability search by product internally."
          />
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="References" />
        <CardBody>
          {vulnerability.references.length === 0 ? (
            <p className="text-sm text-text-muted">No references recorded.</p>
          ) : (
            <ul className="flex flex-col gap-1.5 text-sm">
              {vulnerability.references.map((ref) => (
                <li key={ref} className="truncate">
                  <a href={ref} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
                    {ref}
                  </a>
                </li>
              ))}
            </ul>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Source history" description="What each upstream source reported" />
        <CardBody className="p-0">
          {vulnerability.source_records.length === 0 ? (
            <div className="p-4">
              <p className="text-sm text-text-muted">No per-source records recorded.</p>
            </div>
          ) : (
            <TableContainer>
              <Table>
                <THead>
                  <TR>
                    <TH>Source</TH>
                    <TH>CVSS</TH>
                    <TH>EPSS</TH>
                    <TH>KEV</TH>
                    <TH>First seen</TH>
                    <TH>Last seen</TH>
                  </TR>
                </THead>
                <TBody>
                  {vulnerability.source_records.map((record) => (
                    <TR key={record.source}>
                      <TD>{titleCase(record.source)}</TD>
                      <TD>{formatNumber(record.cvss_score, 1)}</TD>
                      <TD>{formatPercent(record.epss_score)}</TD>
                      <TD>{record.kev_listed === null ? "—" : record.kev_listed ? "Yes" : "No"}</TD>
                      <TD>{formatDateTime(record.first_seen_at)}</TD>
                      <TD>{formatDateTime(record.last_seen_at)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </TableContainer>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Field change history" description="What changed, from which source, and when" />
        <CardBody className="p-0">
          {!historyResult.ok ? (
            <div className="p-4">
              <ErrorState error={historyResult.error} />
            </div>
          ) : historyResult.data.history.length === 0 ? (
            <div className="p-4">
              <p className="text-sm text-text-muted">No field changes recorded yet.</p>
            </div>
          ) : (
            <TableContainer>
              <Table>
                <THead>
                  <TR>
                    <TH>Field</TH>
                    <TH>From</TH>
                    <TH>To</TH>
                    <TH>Source</TH>
                    <TH>Observed</TH>
                  </TR>
                </THead>
                <TBody>
                  {historyResult.data.history.map((entry, i) => (
                    <TR key={i}>
                      <TD>{entry.field}</TD>
                      <TD className="max-w-xs truncate">{entry.old_value ?? "—"}</TD>
                      <TD className="max-w-xs truncate">{entry.new_value ?? "—"}</TD>
                      <TD>{titleCase(entry.source)}</TD>
                      <TD title={formatDateTime(entry.observed_at)}>{formatDateTime(entry.observed_at)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </TableContainer>
          )}
        </CardBody>
      </Card>
    </div>
  );
}

function ScoreStat({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-xs font-medium tracking-wide text-text-muted uppercase">{label}</p>
      <p className={mono ? "mt-0.5 font-mono text-xs break-all text-foreground" : "mt-0.5 text-foreground"}>{value}</p>
    </div>
  );
}
