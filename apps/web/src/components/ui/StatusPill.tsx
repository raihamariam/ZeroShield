import { Badge, type BadgeVariant } from "./Badge";
import { titleCase } from "@/lib/utils/format";

/** Maps every status/label string that appears across job/run/version/verdict/priority
 * states (see src/zeroshield/models/enums.py and src/zeroshield/models/vulnerability.py
 * for the authoritative enum values) to a consistent Badge variant, so the same word
 * always reads the same color everywhere in the app. Unknown values fall back to
 * "neutral" rather than guessing. */
const STATUS_VARIANTS: Record<string, BadgeVariant> = {
  // JobStatus / RunEventType
  queued: "neutral",
  preparing: "info",
  safety_check: "info",
  running: "info",
  running_baseline: "info",
  running_mitigation: "info",
  analysing: "info",
  generating_evidence: "info",
  completed: "success",
  denied: "danger",
  failed: "danger",
  // ExperimentVersionStatus (Studio workflow)
  draft: "neutral",
  ready_for_review: "warning",
  under_review: "warning",
  approved: "success",
  rejected: "danger",
  retired: "neutral",
  // ApprovalStatus (V1 trusted-core experiments)
  pending_review: "warning",
  revision_required: "warning",
  closed: "neutral",
  // VerdictLabel
  effective: "success",
  partially_effective: "warning",
  ineffective: "danger",
  regression: "danger",
  inconclusive: "neutral",
  // SupportStatus (priority queue)
  supported: "success",
  partially_supported: "warning",
  unsupported: "neutral",
  // IntelligenceSyncStatus
  partial: "warning",
  // PriorityLabel (priority queue / Mission Control)
  critical: "danger",
  high: "warning",
  medium: "info",
  low: "neutral",
  // RevalidationStatus (V2 Phase 5)
  pending: "warning",
  dismissed: "neutral",
};

export function StatusPill({ status, className }: { status: string; className?: string }) {
  const variant = STATUS_VARIANTS[status.toLowerCase()] ?? "neutral";
  return (
    <Badge variant={variant} className={className}>
      {titleCase(status)}
    </Badge>
  );
}
