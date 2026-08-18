import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Badge, Card, CardBody, CardHeader, ErrorState, StatusPill } from "@/components/ui";
import { RunExperimentPanel } from "@/components/features/RunExperimentPanel";
import { ApiError } from "@/lib/api/client";
import { evidenceApi, experimentsApi, studioApi } from "@/lib/api";
import type { MetricsSummary } from "@/lib/api/types";
import { formatDateTime, formatDomain, formatMs, formatNumber, formatPercent, titleCase } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export async function generateMetadata(props: PageProps<"/experiments/[experimentId]">): Promise<Metadata> {
  const { experimentId } = await props.params;
  return { title: experimentId };
}

const METRIC_ROWS: { key: keyof MetricsSummary; label: string; format: "percent" | "ms"; higherIsBetter: boolean | null }[] = [
  { key: "processing_success_rate", label: "Processing success", format: "percent", higherIsBetter: true },
  { key: "block_rate", label: "Block rate", format: "percent", higherIsBetter: true },
  { key: "valid_acceptance_rate", label: "Valid acceptance rate", format: "percent", higherIsBetter: true },
  { key: "false_positive_rate", label: "False-positive rate", format: "percent", higherIsBetter: false },
  { key: "false_negative_rate", label: "False-negative rate", format: "percent", higherIsBetter: false },
  { key: "parser_reach_rate", label: "Parser exposure rate", format: "percent", higherIsBetter: null },
  { key: "mean_latency_ms", label: "Mean latency", format: "ms", higherIsBetter: false },
  { key: "log_completeness_rate", label: "Log completeness rate", format: "percent", higherIsBetter: true },
];

async function settle<T>(p: Promise<T>) {
  try {
    return { ok: true as const, data: await p };
  } catch (error) {
    return { ok: false as const, error };
  }
}

export default async function ExperimentDetailPage(props: PageProps<"/experiments/[experimentId]">) {
  const { experimentId } = await props.params;

  let experiment;
  try {
    experiment = await experimentsApi.getExperiment(experimentId);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    return <ErrorState error={error} />;
  }

  const [verdict, results, evidence, versions] = await Promise.all([
    settle(experimentsApi.getExperimentVerdict(experimentId)),
    settle(evidenceApi.getResults(experimentId)),
    settle(evidenceApi.getEvidence(experimentId)),
    settle(studioApi.listExperimentVersions({ experiment_id: experimentId })),
  ]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-xl font-semibold text-foreground">{experiment.experiment_id}</h1>
          <Badge variant="neutral">{formatDomain(experiment.domain)}</Badge>
          <StatusPill status={experiment.approval_status} />
        </div>
        <p className="mt-1 text-sm text-text-muted">{experiment.title}</p>
      </div>

      <Card>
        <CardHeader title="Research" />
        <CardBody className="flex flex-col gap-3 text-sm">
          <p className="text-foreground">{experiment.description}</p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Detail label="Failure pattern" value={experiment.failure_pattern} />
            <Detail label="Root cause" value={titleCase(experiment.root_cause)} />
            <Detail label="Vendor mitigation" value={experiment.vendor_mitigation} />
            <Detail label="Mitigation gap" value={experiment.mitigation_gap} />
            <Detail label="Baseline strategy" value={experiment.baseline_strategy} mono />
            <Detail label="Mitigation strategy" value={experiment.mitigation_strategy} mono />
            <Detail label="Safety level" value={titleCase(experiment.safety_level)} />
          </div>
          <Detail label="Research question" value={experiment.research_question} />
          <Detail label="Hypothesis" value={experiment.hypothesis} />
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Related CVEs" />
        <CardBody>
          {experiment.related_cves.length === 0 ? (
            <p className="text-sm text-text-muted">No CVEs linked.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {experiment.related_cves.map((c) => (
                <Link
                  key={c.cve_id}
                  href={`/vulnerabilities/${c.cve_id}`}
                  className="flex items-center gap-1.5 rounded-lg border border-border px-2.5 py-1.5 text-sm hover:bg-surface-muted"
                >
                  <span className="font-medium text-accent">{c.cve_id}</span>
                  {c.cisa_kev ? <Badge variant="danger">KEV</Badge> : null}
                  {c.cvss_score !== null ? <span className="text-text-muted">CVSS {formatNumber(c.cvss_score, 1)}</span> : null}
                </Link>
              ))}
            </div>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Submit a run" description="Queues an async baseline + mitigation run" />
        <CardBody>
          <RunExperimentPanel experimentId={experimentId} />
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Verdict" description="Deterministic, threshold-based - never AI-decided" />
        <CardBody>
          {!verdict.ok ? (
            verdict.error instanceof ApiError && verdict.error.status === 404 ? (
              <p className="text-sm text-text-muted">No completed run yet - a verdict appears once one finishes.</p>
            ) : (
              <ErrorState error={verdict.error} />
            )
          ) : (
            <div className="flex flex-col gap-3 text-sm">
              <StatusPill status={verdict.data.label} />
              <ul className="list-disc space-y-1 pl-5 text-foreground">
                {verdict.data.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
              {verdict.data.failed_criteria.length > 0 ? (
                <p className="text-text-muted">
                  Failed criteria: <span className="font-mono text-xs">{verdict.data.failed_criteria.join(", ")}</span>
                </p>
              ) : null}
              <details>
                <summary className="cursor-pointer text-xs font-medium text-text-muted">Thresholds used</summary>
                <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-3">
                  {Object.entries(verdict.data.thresholds_used).map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-2">
                      <dt className="text-text-muted">{k}</dt>
                      <dd className="font-mono text-foreground">{v}</dd>
                    </div>
                  ))}
                </dl>
              </details>
              {verdict.data.limitations.length > 0 ? (
                <ul className="list-disc space-y-1 pl-5 text-xs text-text-muted">
                  {verdict.data.limitations.map((l, i) => (
                    <li key={i}>{l}</li>
                  ))}
                </ul>
              ) : null}
              <p className="text-xs text-text-muted">Generated {formatDateTime(verdict.data.generated_at)}</p>
            </div>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Results" description="Latest baseline-vs-mitigation comparison" />
        <CardBody>
          {!results.ok ? (
            results.error instanceof ApiError && results.error.status === 404 ? (
              <p className="text-sm text-text-muted">No results yet - run this experiment to generate them.</p>
            ) : (
              <ErrorState error={results.error} />
            )
          ) : (
            <div className="flex flex-col gap-4">
              <div className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-3">
                <Detail label="Total cases" value={formatNumber(results.data.total_cases)} />
                <Detail
                  label="Block rate improvement"
                  value={`${results.data.block_rate_improvement >= 0 ? "+" : ""}${formatPercent(results.data.block_rate_improvement)}`}
                />
                <Detail
                  label="Latency overhead"
                  value={`${results.data.latency_overhead_ms >= 0 ? "+" : ""}${formatMs(results.data.latency_overhead_ms)}`}
                />
              </div>

              <div className="overflow-x-auto">
                <table className="w-full min-w-max border-collapse text-sm">
                  <thead className="border-b border-border text-left">
                    <tr>
                      <th className="px-3 py-2 font-medium text-text-muted">Metric</th>
                      <th className="px-3 py-2 font-medium text-text-muted">Baseline</th>
                      <th className="px-3 py-2 font-medium text-text-muted">Mitigation</th>
                      <th className="px-3 py-2 font-medium text-text-muted">Change</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {METRIC_ROWS.map((row) => {
                      const baseline = results.data.baseline_metrics[row.key];
                      const mitigation = results.data.mitigation_metrics[row.key];
                      const delta = mitigation - baseline;
                      const good = row.higherIsBetter === null ? null : row.higherIsBetter ? delta >= 0 : delta <= 0;
                      const fmt = (v: number) => (row.format === "percent" ? formatPercent(v) : formatMs(v));
                      return (
                        <tr key={row.key}>
                          <td className="px-3 py-2 text-foreground">{row.label}</td>
                          <td className="px-3 py-2 text-text-muted">{fmt(baseline)}</td>
                          <td className="px-3 py-2 font-medium text-foreground">{fmt(mitigation)}</td>
                          <td className={`px-3 py-2 font-medium ${good === null ? "text-text-muted" : good ? "text-success" : "text-danger"}`}>
                            {delta >= 0 ? "+" : ""}
                            {fmt(delta)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <p className="text-xs text-text-muted">
                Case-category breakdown (valid/malformed/boundary) is not exposed by the results API - only
                aggregate metrics are available here.
              </p>

              {results.data.limitations.length > 0 ? (
                <ul className="list-disc space-y-1 pl-5 text-xs text-text-muted">
                  {results.data.limitations.map((l, i) => (
                    <li key={i}>{l}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader
          title="Evidence"
          description="Provenance for the latest run"
          action={
            <Link href={`/evidence-vault/${experimentId}`} className="text-sm font-medium text-accent hover:underline">
              Full evidence →
            </Link>
          }
        />
        <CardBody>
          {!evidence.ok ? (
            evidence.error instanceof ApiError && evidence.error.status === 404 ? (
              <p className="text-sm text-text-muted">No evidence yet - run this experiment to generate it.</p>
            ) : (
              <ErrorState error={evidence.error} />
            )
          ) : (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              {[evidence.data.baseline, evidence.data.mitigation].map((run) => (
                <div key={run.run_id} className="rounded-lg border border-border p-3 text-sm">
                  <div className="flex items-center justify-between">
                    <p className="font-medium text-foreground">{run.mode === "baseline" ? "Baseline" : "Mitigation"}</p>
                    {run.integrity_verified ? (
                      <Badge variant="success">Integrity verified</Badge>
                    ) : (
                      <Badge variant="danger">Integrity check failed</Badge>
                    )}
                  </div>
                  <p className="mt-1 font-mono text-xs text-text-muted">{run.run_id}</p>
                  <p className="mt-1 text-xs text-text-muted">Strategy: {run.strategy_id}</p>
                  <p className="text-xs text-text-muted">Git commit: {run.git_commit}</p>
                </div>
              ))}
            </div>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader
          title="Version history"
          description="Experiment Studio draft/review lifecycle"
          action={
            <Link href={`/approvals?experiment_id=${experimentId}`} className="text-sm font-medium text-accent hover:underline">
              View in Approvals →
            </Link>
          }
        />
        <CardBody>
          {!versions.ok ? (
            <ErrorState error={versions.error} />
          ) : versions.data.versions.length === 0 ? (
            <p className="text-sm text-text-muted">
              No Experiment Studio versions recorded for this experiment - it predates the versioning workflow or
              was authored directly.
            </p>
          ) : (
            <ul className="flex flex-col gap-2">
              {versions.data.versions
                .sort((a, b) => b.version_number - a.version_number)
                .map((v) => (
                  <li key={v.version_id} className="flex items-center justify-between gap-3 rounded-lg border border-border px-3 py-2 text-sm">
                    <Link href={`/approvals/${encodeURIComponent(v.version_id)}`} className="font-medium text-accent hover:underline">
                      v{v.version_number}
                    </Link>
                    <div className="flex items-center gap-3">
                      <span className="text-text-muted">{v.created_by}</span>
                      <StatusPill status={v.status} />
                    </div>
                  </li>
                ))}
            </ul>
          )}
        </CardBody>
      </Card>
    </div>
  );
}

function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-xs font-medium tracking-wide text-text-muted uppercase">{label}</p>
      <p className={mono ? "mt-0.5 font-mono text-xs text-foreground" : "mt-0.5 text-foreground"}>{value}</p>
    </div>
  );
}
