import type { Metadata } from "next";
import { Badge, EmptyState, ErrorState } from "@/components/ui";
import { Select } from "@/components/ui/Field";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { authApi } from "@/lib/api";
import { formatDateTime, titleCase } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Audit Trail" };

const COMMON_ACTIONS = [
  "auth.login_success", "auth.login_failure", "auth.logout", "auth.account_locked",
  "user.created", "user.role_changed", "user.deactivated", "user.reactivated",
  "experiment_version.created", "experiment_version.approved", "experiment_version.rejected",
  "experiment_version.self_approval_blocked", "run.submitted", "run.denied", "run.failed",
  "evidence.created", "evidence.verified", "intelligence.sync_initiated", "ai_assessment.reviewed",
  "asset.created", "asset.updated", "revalidation_candidate.approved", "revalidation_candidate.dismissed",
];

function firstValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function AuditTrailPage(props: PageProps<"/audit-trail">) {
  const raw = await props.searchParams;
  const action = firstValue(raw.action);

  let events;
  let total = 0;
  let error: unknown = null;
  try {
    const result = await authApi.listAuditEvents({ action: action || undefined, limit: 100 });
    events = result.events;
    total = result.total;
  } catch (err) {
    error = err;
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Audit Trail</h1>
        <p className="mt-1 text-sm text-text-muted">
          ADMIN only. Immutable - every security/login event, experiment/version change, review/approval/rejection,
          run submission/denial/failure, evidence creation/verification, sync initiation, configuration change,
          user/role change, and AI assessment review is recorded here with actor, target, timestamp, and correlation
          ID (Step 3).
        </p>
      </div>

      <form method="GET" action="/audit-trail" className="flex max-w-sm items-end gap-2">
        <div className="flex-1">
          <label htmlFor="action" className="mb-1.5 block text-sm font-medium text-foreground">
            Action
          </label>
          <Select id="action" name="action" defaultValue={action ?? ""}>
            <option value="">All actions</option>
            {COMMON_ACTIONS.map((a) => (
              <option key={a} value={a}>
                {titleCase(a.replace(/\./g, " "))}
              </option>
            ))}
          </Select>
        </div>
        <button type="submit" className="rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-accent-foreground hover:opacity-90">
          Filter
        </button>
      </form>

      {error ? (
        <ErrorState error={error} />
      ) : !events || events.length === 0 ? (
        <EmptyState title="No audit events" description="Nothing matches this filter yet." />
      ) : (
        <>
          <p className="text-xs text-text-muted">
            Showing {events.length} of {total} events, most recent first.
          </p>
          <TableContainer>
            <Table>
              <THead>
                <TR>
                  <TH>When</TH>
                  <TH>Actor</TH>
                  <TH>Action</TH>
                  <TH>Target</TH>
                  <TH>Detail</TH>
                </TR>
              </THead>
              <TBody>
                {events.map((e) => (
                  <TR key={e.audit_id}>
                    <TD title={formatDateTime(e.occurred_at)}>{formatDateTime(e.occurred_at)}</TD>
                    <TD>
                      {e.actor_username ?? <span className="text-text-muted">system</span>}
                      {e.actor_role ? <span className="ml-1 text-xs text-text-muted">({e.actor_role})</span> : null}
                    </TD>
                    <TD>
                      <Badge variant="neutral">{titleCase(e.action.replace(/\./g, " "))}</Badge>
                    </TD>
                    <TD>
                      {e.target_type ? (
                        <span>
                          {e.target_type}
                          {e.target_id ? `:${e.target_id}` : ""}
                        </span>
                      ) : (
                        "—"
                      )}
                    </TD>
                    <TD className="max-w-sm truncate" title={JSON.stringify(e.metadata)}>
                      {Object.keys(e.metadata).length > 0 ? JSON.stringify(e.metadata) : "—"}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </TableContainer>
        </>
      )}
    </div>
  );
}
