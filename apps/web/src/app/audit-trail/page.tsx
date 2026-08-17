import type { Metadata } from "next";
import { EmptyState } from "@/components/ui";

export const metadata: Metadata = { title: "Audit Trail" };

export default function AuditTrailPage() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-semibold text-foreground">Audit Trail</h1>
        <p className="mt-1 text-sm text-text-muted">Governance</p>
      </div>
      <EmptyState
        title="Not built yet"
        description="A consolidated, tamper-evident audit trail across approvals, runs, and evidence is planned for Phase 6 (governance/RBAC). Today, the underlying facts already exist and are viewable individually: approval decisions on each experiment version's Approvals page, and run history on the Runs page."
      />
    </div>
  );
}
