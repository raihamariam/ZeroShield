import type { Metadata } from "next";
import type { ReactNode } from "react";
import Link from "next/link";
import { Badge, Card, CardBody, CardHeader, EmptyState, ErrorState, StatTile, StatusPill } from "@/components/ui";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { analystApi, controlsApi, experimentsApi, intelligenceApi, jobsApi, revalidationApi, studioApi } from "@/lib/api";
import type {
  AIAssessmentResponse,
  ExperimentVersionResponse,
  JobStatusResponse,
  ValidationCandidateResponse,
  VerdictResponse,
} from "@/lib/api/types";
import { formatDateTime, formatDomain, formatPercent, formatRelativeToNow, titleCase } from "@/lib/utils/format";

// Mission Control is a live operational view - never serve a cached snapshot.
export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Mission Control" };

type Settled<T> = { ok: true; data: T } | { ok: false; error: unknown };

async function settle<T>(promise: Promise<T>): Promise<Settled<T>> {
  try {
    return { ok: true, data: await promise };
  } catch (error) {
    return { ok: false, error };
  }
}

function mapSettled<T, U>(result: Settled<T>, project: (value: T) => U): Settled<U> {
  return result.ok ? { ok: true, data: project(result.data) } : result;
}

/** Merges N settled list fetches into one - if *any* of them failed, the combined
 * metric is treated as unavailable rather than silently showing a partial (and
 * therefore misleading) count or table. */
function combine<T>(...results: Settled<T[]>[]): Settled<T[]> {
  const failed = results.find((r): r is { ok: false; error: unknown } => !r.ok);
  if (failed) return failed;
  return { ok: true, data: results.flatMap((r) => (r.ok ? r.data : [])) };
}

const PANEL_ROW_LIMIT = 5;

/** No dedicated "active regressions" endpoint exists - Step 10's regression check
 * is per-control (GET /controls/{id}/effectiveness). The control inventory is
 * deliberately small (Step 7/8's own framing), so checking all of them here stays
 * a handful of calls. One control's effectiveness failing to load is dropped
 * silently rather than failing the whole panel - Mission Control degrades per
 * signal, not all-or-nothing, for this one summary. */
async function findRegressedControls(): Promise<{ controlId: string; controlName: string; reasons: string[] }[]> {
  const controls = await controlsApi.listControls();
  const results = await Promise.all(
    controls.controls.map(async (c) => {
      try {
        const eff = await controlsApi.getControlEffectiveness(c.control_id);
        return eff.regression?.is_regression ? { controlId: c.control_id, controlName: c.name, reasons: eff.regression.reasons } : null;
      } catch {
        return null;
      }
    })
  );
  return results.filter((r): r is { controlId: string; controlName: string; reasons: string[] } => r !== null);
}

export default async function MissionControlPage() {
  const [
    priorityQueue,
    kevSummary,
    runningJobs,
    queuedJobs,
    failedJobs,
    deniedJobs,
    completedJobs,
    readyForReview,
    underReview,
    unreviewedAssessments,
    pendingRevalidations,
    regressedControls,
  ] = await Promise.all([
    settle(intelligenceApi.getPriorityQueue({ limit: 200 })),
    settle(intelligenceApi.listVulnerabilities({ kev: true, limit: 1 })),
    settle(jobsApi.listJobs({ status: "running", limit: 50 })),
    settle(jobsApi.listJobs({ status: "queued", limit: 50 })),
    settle(jobsApi.listJobs({ status: "failed", limit: 20 })),
    settle(jobsApi.listJobs({ status: "denied", limit: 20 })),
    settle(jobsApi.listJobs({ status: "completed", limit: 5 })),
    settle(studioApi.listExperimentVersions({ status: "ready_for_review" })),
    settle(studioApi.listExperimentVersions({ status: "under_review" })),
    settle(analystApi.listAssessments({ reviewed: false })),
    settle(revalidationApi.listRevalidationCandidates({ status: "pending" })),
    settle(findRegressedControls()),
  ]);

  const activeRuns = combine(
    mapSettled(runningJobs, (r) => r.jobs),
    mapSettled(queuedJobs, (r) => r.jobs)
  );
  if (activeRuns.ok) activeRuns.data.sort((a, b) => b.submitted_at.localeCompare(a.submitted_at));

  const failedOrDenied = combine(
    mapSettled(failedJobs, (r) => r.jobs),
    mapSettled(deniedJobs, (r) => r.jobs)
  );
  if (failedOrDenied.ok) failedOrDenied.data.sort((a, b) => b.updated_at.localeCompare(a.updated_at));

  const pendingApprovals = combine(
    mapSettled(readyForReview, (r) => r.versions),
    mapSettled(underReview, (r) => r.versions)
  );
  if (pendingApprovals.ok) pendingApprovals.data.sort((a, b) => b.updated_at.localeCompare(a.updated_at));

  // Verdicts don't have a list endpoint - derive "recent" from the latest completed
  // jobs and look each one up. A single experiment's verdict lookup failing (e.g. its
  // evidence hasn't finished writing) must not take down the whole panel.
  const recentVerdicts: { job: JobStatusResponse; verdict: Settled<VerdictResponse> }[] = completedJobs.ok
    ? await Promise.all(
        completedJobs.data.jobs.map(async (job) => ({
          job,
          verdict: await settle(experimentsApi.getExperimentVerdict(job.experiment_id)),
        }))
      )
    : [];

  const criticalHighCandidates = priorityQueue.ok
    ? priorityQueue.data.candidates.filter((c) => c.priority_label === "critical" || c.priority_label === "high")
    : null;

  const coveredCandidates = priorityQueue.ok
    ? priorityQueue.data.candidates.filter((c) => c.existing_experiment_ids.length > 0)
    : null;
  const coverageRate =
    priorityQueue.ok && priorityQueue.data.candidates.length > 0
      ? coveredCandidates!.length / priorityQueue.data.candidates.length
      : null;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Mission Control</h1>
        <p className="mt-1 text-sm text-text-muted">
          Live view of validation priority, in-flight runs, and outstanding approvals across ZeroShield.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-9">
        <StatTile
          label="Critical / high priority"
          value={criticalHighCandidates ? criticalHighCandidates.length : "—"}
          tone={criticalHighCandidates && criticalHighCandidates.length > 0 ? "danger" : "neutral"}
          hint={
            priorityQueue.ok && priorityQueue.data.total > priorityQueue.data.candidates.length
              ? `of ${priorityQueue.data.total} in queue`
              : "in the priority queue"
          }
          href="/priority-queue"
        />
        <StatTile
          label="KEV matches"
          value={kevSummary.ok ? kevSummary.data.total : "—"}
          tone={kevSummary.ok && kevSummary.data.total > 0 ? "danger" : "neutral"}
          hint="CISA Known Exploited Vulnerabilities"
          href="/vulnerabilities?kev=true"
        />
        <StatTile
          label="Validation coverage"
          value={coverageRate !== null ? formatPercent(coverageRate, 0) : "—"}
          hint={
            priorityQueue.ok
              ? `${coveredCandidates!.length} of ${priorityQueue.data.candidates.length} priority CVEs have a linked experiment`
              : undefined
          }
          href="/priority-queue"
        />
        <StatTile
          label="Active runs"
          value={activeRuns.ok ? activeRuns.data.length : "—"}
          hint="queued + running"
          href="/runs?status=running"
        />
        <StatTile
          label="Pending approvals"
          value={pendingApprovals.ok ? pendingApprovals.data.length : "—"}
          tone={pendingApprovals.ok && pendingApprovals.data.length > 0 ? "warning" : "neutral"}
          hint="awaiting a reviewer decision"
          href="/approvals"
        />
        <StatTile
          label="Failed / denied runs"
          value={failedOrDenied.ok ? failedOrDenied.data.length : "—"}
          tone={failedOrDenied.ok && failedOrDenied.data.length > 0 ? "danger" : "neutral"}
          hint="most recent"
          href="/runs?status=failed"
        />
        <StatTile
          label="New AI assessments"
          value={unreviewedAssessments.ok ? unreviewedAssessments.data.assessments.length : "—"}
          tone={unreviewedAssessments.ok && unreviewedAssessments.data.assessments.length > 0 ? "warning" : "neutral"}
          hint="awaiting human review"
          href="/analyst"
        />
        <StatTile
          label="Active regressions"
          value={regressedControls.ok ? regressedControls.data.length : "—"}
          tone={regressedControls.ok && regressedControls.data.length > 0 ? "danger" : "neutral"}
          hint="controls, deterministically detected"
          href="/controls"
        />
        <StatTile
          label="Pending revalidations"
          value={pendingRevalidations.ok ? pendingRevalidations.data.candidates.length : "—"}
          tone={pendingRevalidations.ok && pendingRevalidations.data.candidates.length > 0 ? "warning" : "neutral"}
          hint="candidates awaiting a decision"
          href="/revalidation"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Critical validation candidates" description="Highest ZeroShield priority score first" viewAllHref="/priority-queue">
          {!priorityQueue.ok ? (
            <ErrorState error={priorityQueue.error} />
          ) : priorityQueue.data.candidates.length === 0 ? (
            <EmptyState title="No priority candidates" description="The priority queue is currently empty." />
          ) : (
            <TableContainer>
              <Table>
                <THead>
                  <TR>
                    <TH>CVE</TH>
                    <TH>Domain</TH>
                    <TH>Priority</TH>
                    <TH>Support</TH>
                    <TH>Linked experiments</TH>
                  </TR>
                </THead>
                <TBody>
                  {priorityQueue.data.candidates.slice(0, PANEL_ROW_LIMIT).map((c: ValidationCandidateResponse) => (
                    <TR key={c.cve_id}>
                      <TD>
                        <Link href={`/vulnerabilities/${c.cve_id}`} className="font-medium text-accent hover:underline">
                          {c.cve_id}
                        </Link>
                      </TD>
                      <TD>{c.domain ? formatDomain(c.domain) : "—"}</TD>
                      <TD>
                        <StatusPill status={c.priority_label} />
                      </TD>
                      <TD>
                        <StatusPill status={c.support_status} />
                      </TD>
                      <TD>{c.existing_experiment_ids.length}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </TableContainer>
          )}
        </Panel>

        <Panel title="Pending approvals" description="Experiment versions awaiting review" viewAllHref="/approvals">
          {!pendingApprovals.ok ? (
            <ErrorState error={pendingApprovals.error} />
          ) : pendingApprovals.data.length === 0 ? (
            <EmptyState title="Nothing pending" description="No experiment versions are waiting on a reviewer." />
          ) : (
            <TableContainer>
              <Table>
                <THead>
                  <TR>
                    <TH>Experiment</TH>
                    <TH>Version</TH>
                    <TH>Status</TH>
                    <TH>Created by</TH>
                    <TH>Updated</TH>
                  </TR>
                </THead>
                <TBody>
                  {pendingApprovals.data.slice(0, PANEL_ROW_LIMIT).map((v: ExperimentVersionResponse) => (
                    <TR key={v.version_id}>
                      <TD>
                        <Link href={`/experiments/${v.experiment_id}`} className="font-medium text-accent hover:underline">
                          {v.experiment_id}
                        </Link>
                      </TD>
                      <TD>v{v.version_number}</TD>
                      <TD>
                        <StatusPill status={v.status} />
                      </TD>
                      <TD>{v.created_by}</TD>
                      <TD title={formatDateTime(v.updated_at)}>{formatRelativeToNow(v.updated_at)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </TableContainer>
          )}
        </Panel>

        <Panel title="Active runs" description="Queued and in-progress validation jobs" viewAllHref="/runs">
          {!activeRuns.ok ? (
            <ErrorState error={activeRuns.error} />
          ) : activeRuns.data.length === 0 ? (
            <EmptyState title="No active runs" description="Nothing is queued or running right now." />
          ) : (
            <TableContainer>
              <Table>
                <THead>
                  <TR>
                    <TH>Job</TH>
                    <TH>Experiment</TH>
                    <TH>Status</TH>
                    <TH>Submitted</TH>
                  </TR>
                </THead>
                <TBody>
                  {activeRuns.data.slice(0, PANEL_ROW_LIMIT).map((job: JobStatusResponse) => (
                    <TR key={job.job_id}>
                      <TD>
                        <Link href={`/runs/${job.job_id}`} className="font-medium text-accent hover:underline">
                          {job.job_id}
                        </Link>
                      </TD>
                      <TD>{job.experiment_id}</TD>
                      <TD>
                        <StatusPill status={job.status} />
                      </TD>
                      <TD title={formatDateTime(job.submitted_at)}>{formatRelativeToNow(job.submitted_at)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </TableContainer>
          )}
        </Panel>

        <Panel title="Failed / denied runs" description="Most recent unsuccessful jobs" viewAllHref="/runs?status=failed">
          {!failedOrDenied.ok ? (
            <ErrorState error={failedOrDenied.error} />
          ) : failedOrDenied.data.length === 0 ? (
            <EmptyState title="No failures" description="No runs have failed or been denied recently." />
          ) : (
            <TableContainer>
              <Table>
                <THead>
                  <TR>
                    <TH>Job</TH>
                    <TH>Experiment</TH>
                    <TH>Status</TH>
                    <TH>Reason</TH>
                    <TH>Updated</TH>
                  </TR>
                </THead>
                <TBody>
                  {failedOrDenied.data.slice(0, PANEL_ROW_LIMIT).map((job: JobStatusResponse) => (
                    <TR key={job.job_id}>
                      <TD>
                        <Link href={`/runs/${job.job_id}`} className="font-medium text-accent hover:underline">
                          {job.job_id}
                        </Link>
                      </TD>
                      <TD>{job.experiment_id}</TD>
                      <TD>
                        <StatusPill status={job.status} />
                      </TD>
                      <TD className="max-w-xs truncate" title={job.error ?? undefined}>
                        {job.error ?? "—"}
                      </TD>
                      <TD title={formatDateTime(job.updated_at)}>{formatRelativeToNow(job.updated_at)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </TableContainer>
          )}
        </Panel>

        <Panel
          title="Recent verdicts"
          description="Deterministic outcome of the latest completed runs"
          viewAllHref="/runs?status=completed"
        >
          {!completedJobs.ok ? (
            <ErrorState error={completedJobs.error} />
          ) : recentVerdicts.length === 0 ? (
            <EmptyState title="No completed runs yet" description="Verdicts appear here once a run finishes." />
          ) : (
            <ul className="divide-y divide-border">
              {recentVerdicts.map(({ job, verdict }) => (
                <li key={job.job_id} className="flex items-center justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <Link href={`/experiments/${job.experiment_id}`} className="truncate font-medium text-accent hover:underline">
                      {job.experiment_id}
                    </Link>
                    <p className="text-xs text-text-muted">{formatRelativeToNow(job.updated_at)}</p>
                  </div>
                  {verdict.ok ? <StatusPill status={verdict.data.label} /> : <Badge variant="neutral">Unavailable</Badge>}
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="New AI assessments" description="Advisory only, awaiting human review" viewAllHref="/analyst">
          {!unreviewedAssessments.ok ? (
            <ErrorState error={unreviewedAssessments.error} />
          ) : unreviewedAssessments.data.assessments.length === 0 ? (
            <EmptyState title="Nothing awaiting review" description="Every AI assessment has been reviewed." />
          ) : (
            <ul className="divide-y divide-border">
              {unreviewedAssessments.data.assessments.slice(0, PANEL_ROW_LIMIT).map((a: AIAssessmentResponse) => (
                <li key={a.assessment_id} className="flex items-center justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <Link
                      href={a.subject_type === "vulnerability" ? `/vulnerabilities/${a.subject_id}` : `/controls/${a.subject_id}`}
                      className="truncate font-medium text-accent hover:underline"
                    >
                      {a.subject_id}
                    </Link>
                    <p className="text-xs text-text-muted">{titleCase(a.assessment_type)}</p>
                  </div>
                  <Badge variant="warning">{formatPercent(a.confidence, 0)} confidence</Badge>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Active regressions" description="Deterministically detected control degradations" viewAllHref="/controls">
          {!regressedControls.ok ? (
            <ErrorState error={regressedControls.error} />
          ) : regressedControls.data.length === 0 ? (
            <EmptyState title="No active regressions" description="No control's effectiveness has deteriorated between its two most recent validations." />
          ) : (
            <ul className="divide-y divide-border">
              {regressedControls.data.slice(0, PANEL_ROW_LIMIT).map((r) => (
                <li key={r.controlId} className="flex items-center justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <Link href={`/controls/${r.controlId}`} className="truncate font-medium text-accent hover:underline">
                      {r.controlName}
                    </Link>
                    <p className="truncate text-xs text-text-muted">{r.reasons[0]}</p>
                  </div>
                  <StatusPill status="regression" />
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Pending revalidations" description="Awaiting an approve/dismiss decision" viewAllHref="/revalidation">
          {!pendingRevalidations.ok ? (
            <ErrorState error={pendingRevalidations.error} />
          ) : pendingRevalidations.data.candidates.length === 0 ? (
            <EmptyState title="Nothing pending" description="No revalidation candidates are awaiting a decision." />
          ) : (
            <ul className="divide-y divide-border">
              {pendingRevalidations.data.candidates.slice(0, PANEL_ROW_LIMIT).map((c) => (
                <li key={c.candidate_id} className="flex items-center justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <Link href={`/controls/${c.control_id}`} className="truncate font-medium text-accent hover:underline">
                      {c.control_id}
                    </Link>
                    <p className="truncate text-xs text-text-muted">{titleCase(c.trigger_type)}</p>
                  </div>
                  <p className="text-xs text-text-muted">{formatRelativeToNow(c.created_at)}</p>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}

function Panel({
  title,
  description,
  viewAllHref,
  children,
}: {
  title: string;
  description: string;
  viewAllHref: string;
  children: ReactNode;
}) {
  return (
    <Card>
      <CardHeader
        title={title}
        description={description}
        action={
          <Link href={viewAllHref} className="text-sm font-medium text-accent hover:underline">
            View all
          </Link>
        }
      />
      <CardBody className="p-0">{children}</CardBody>
    </Card>
  );
}
