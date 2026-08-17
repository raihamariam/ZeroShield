import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { RegressionExplainButton } from "@/components/features/RegressionExplainButton";
import { Badge, Card, CardBody, CardHeader, EmptyState, ErrorState, StatusPill } from "@/components/ui";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { ApiError } from "@/lib/api/client";
import { controlsApi } from "@/lib/api";
import { formatDateTime, formatDomain, formatPercent } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export async function generateMetadata(props: PageProps<"/controls/[controlId]">): Promise<Metadata> {
  const { controlId } = await props.params;
  return { title: controlId };
}

export default async function ControlDetailPage(props: PageProps<"/controls/[controlId]">) {
  const { controlId } = await props.params;

  let control;
  try {
    control = await controlsApi.getControl(controlId);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    return <ErrorState error={error} />;
  }

  const [versionsResult, effectivenessResult] = await Promise.all([
    controlsApi.listControlVersions(controlId).then(
      (data) => ({ ok: true as const, data }),
      (error: unknown) => ({ ok: false as const, error })
    ),
    controlsApi.getControlEffectiveness(controlId).then(
      (data) => ({ ok: true as const, data }),
      (error: unknown) => ({ ok: false as const, error })
    ),
  ]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-xl font-semibold text-foreground">{control.name}</h1>
          <Badge variant="neutral">{formatDomain(control.domain)}</Badge>
        </div>
        <p className="mt-1 text-sm text-text-muted">
          {control.control_id} · Mitigation strategy: {control.mitigation_strategy_id} · Registered{" "}
          {formatDateTime(control.created_at)}
        </p>
      </div>

      {effectivenessResult.ok && effectivenessResult.data.regression?.is_regression ? (
        <Card className="border-danger-bg">
          <CardHeader title="Regression detected" description="Deterministic - see reasons below" />
          <CardBody>
            <ul className="list-disc space-y-1 pl-5 text-sm text-danger">
              {effectivenessResult.data.regression.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
            <RegressionExplainButton controlId={controlId} />
          </CardBody>
        </Card>
      ) : null}

      <Card>
        <CardHeader title="Effectiveness" description="Step 9: aggregated only within the current control version" />
        <CardBody>
          {!effectivenessResult.ok ? (
            <EmptyState
              title="No validations yet"
              description="This control's effectiveness appears once at least one experiment run using its mitigation strategy has completed."
            />
          ) : (
            <div className="flex flex-col gap-4">
              <div className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
                <Stat label="Current version" value={effectivenessResult.data.current_version_label ?? "—"} />
                <Stat label="Validations (current version)" value={String(effectivenessResult.data.validation_count_current_version)} />
                <Stat label="Total validations" value={String(effectivenessResult.data.total_validation_count)} />
                <Stat
                  label="Mean block-rate improvement"
                  value={formatPercent(effectivenessResult.data.mean_block_rate_improvement_current_version)}
                />
                <Stat
                  label="Latest verdict"
                  value=""
                  pill={effectivenessResult.data.latest_verdict ?? undefined}
                />
                <Stat
                  label="Previous verdict"
                  value=""
                  pill={effectivenessResult.data.previous_verdict ?? undefined}
                />
                <Stat label="Last validated" value={formatDateTime(effectivenessResult.data.last_validated_at)} />
              </div>
              <p className="text-xs text-text-muted">{effectivenessResult.data.comparability_note}</p>
            </div>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Validation trend" description="Most recent validations for the current control version" />
        <CardBody className="p-0">
          {!effectivenessResult.ok || effectivenessResult.data.trend.length === 0 ? (
            <div className="p-4">
              <p className="text-sm text-text-muted">No trend data yet.</p>
            </div>
          ) : (
            <TableContainer>
              <Table>
                <THead>
                  <TR>
                    <TH>Experiment</TH>
                    <TH>Verdict</TH>
                    <TH>Block-rate improvement</TH>
                    <TH>FP rate</TH>
                    <TH>FN rate</TH>
                    <TH>Valid acceptance</TH>
                    <TH>Validated</TH>
                  </TR>
                </THead>
                <TBody>
                  {effectivenessResult.data.trend.map((v) => (
                    <TR key={v.validation_id}>
                      <TD>{v.experiment_id}</TD>
                      <TD>
                        <StatusPill status={v.verdict_label} />
                      </TD>
                      <TD>{formatPercent(v.block_rate_improvement)}</TD>
                      <TD>{formatPercent(v.false_positive_rate)}</TD>
                      <TD>{formatPercent(v.false_negative_rate)}</TD>
                      <TD>{formatPercent(v.valid_acceptance_rate)}</TD>
                      <TD title={formatDateTime(v.validated_at)}>{formatDateTime(v.validated_at)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </TableContainer>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Versions" />
        <CardBody className="p-0">
          {!versionsResult.ok || versionsResult.data.versions.length === 0 ? (
            <div className="p-4">
              <p className="text-sm text-text-muted">No versions recorded.</p>
            </div>
          ) : (
            <TableContainer>
              <Table>
                <THead>
                  <TR>
                    <TH>Version</TH>
                    <TH>Domain pack</TH>
                    <TH>Template</TH>
                    <TH>Created</TH>
                  </TR>
                </THead>
                <TBody>
                  {versionsResult.data.versions.map((v) => (
                    <TR key={v.version_id}>
                      <TD>{v.version_label}</TD>
                      <TD>{v.domain_pack_id}</TD>
                      <TD>
                        {v.template_id} (v{v.template_version})
                      </TD>
                      <TD>{formatDateTime(v.created_at)}</TD>
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

function Stat({ label, value, pill }: { label: string; value: string; pill?: string }) {
  return (
    <div>
      <p className="text-xs font-medium tracking-wide text-text-muted uppercase">{label}</p>
      <div className="mt-0.5">{pill ? <StatusPill status={pill} /> : <span className="text-foreground">{value || "—"}</span>}</div>
    </div>
  );
}
