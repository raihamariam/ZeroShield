import type { Metadata } from "next";
import Link from "next/link";
import { EmptyState, ErrorState, StatusPill } from "@/components/ui";
import { TBody, THead, TD, TH, TR, Table, TableContainer } from "@/components/ui/Table";
import { controlsApi } from "@/lib/api";
import type { ControlResponse } from "@/lib/api/types";
import { formatDateTime, formatDomain } from "@/lib/utils/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Controls" };

type Settled<T> = { ok: true; data: T } | { ok: false; error: unknown };

async function settle<T>(promise: Promise<T>): Promise<Settled<T>> {
  try {
    return { ok: true, data: await promise };
  } catch (error) {
    return { ok: false, error };
  }
}

export default async function ControlsPage() {
  let controls: ControlResponse[];
  let error: unknown = null;
  try {
    controls = (await controlsApi.listControls()).controls;
  } catch (err) {
    error = err;
    controls = [];
  }

  // One effectiveness lookup per control - the inventory is deliberately small
  // (Step 7/8's own framing), so this stays a handful of calls, not a scale problem.
  // A single control's effectiveness failing to load never hides the others.
  const effectiveness = await Promise.all(controls.map((c) => settle(controlsApi.getControlEffectiveness(c.control_id))));

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Controls</h1>
        <p className="mt-1 text-sm text-text-muted">
          Defensive controls (domain + mitigation strategy), derived automatically from every completed validation run.
          Effectiveness is only ever aggregated within one control version - never blended across a version bump.
        </p>
      </div>

      {error ? (
        <ErrorState error={error} />
      ) : controls.length === 0 ? (
        <EmptyState
          title="No controls yet"
          description="A Control/ControlVersion is created automatically the first time an experiment using its mitigation strategy completes a run."
        />
      ) : (
        <TableContainer>
          <Table>
            <THead>
              <TR>
                <TH>Control</TH>
                <TH>Domain</TH>
                <TH>Current version</TH>
                <TH>Validations</TH>
                <TH>Latest verdict</TH>
                <TH>Last validated</TH>
                <TH>Regression</TH>
              </TR>
            </THead>
            <TBody>
              {controls.map((c, i) => {
                const eff = effectiveness[i];
                return (
                  <TR key={c.control_id}>
                    <TD>
                      <Link href={`/controls/${c.control_id}`} className="font-medium text-accent hover:underline">
                        {c.name}
                      </Link>
                    </TD>
                    <TD>{formatDomain(c.domain)}</TD>
                    <TD>{eff.ok ? eff.data.current_version_label ?? "—" : "—"}</TD>
                    <TD>{eff.ok ? eff.data.total_validation_count : "—"}</TD>
                    <TD>{eff.ok && eff.data.latest_verdict ? <StatusPill status={eff.data.latest_verdict} /> : "—"}</TD>
                    <TD>{eff.ok ? formatDateTime(eff.data.last_validated_at) : "No validations yet"}</TD>
                    <TD>
                      {eff.ok && eff.data.regression?.is_regression ? (
                        <StatusPill status="regression" />
                      ) : (
                        <span className="text-text-muted">—</span>
                      )}
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        </TableContainer>
      )}
    </div>
  );
}
