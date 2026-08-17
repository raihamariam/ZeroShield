/**
 * Product information architecture (V2 Phase 4, Step 2). As of V2 Phase 5,
 * the AI Research Analyst, CVE clusters (deterministic correlation - surfaced
 * inline on a vulnerability's own page, not a separate nav item), Asset
 * inventory, Control Effectiveness, and the Revalidation queue all now have
 * real backend capability, so they're real nav items below rather than the
 * placeholders they were in Phase 4. As of V2 Phase 6, Audit Trail is a real
 * viewer (no longer a placeholder) and Users (ADMIN-only, backend-enforced)
 * is new.
 */
export interface NavItem {
  label: string;
  href: string;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: "",
    items: [{ label: "Mission Control", href: "/" }],
  },
  {
    label: "Threat Intelligence",
    items: [
      { label: "Vulnerabilities", href: "/vulnerabilities" },
      { label: "Priority Queue", href: "/priority-queue" },
      { label: "ZeroShield Analyst", href: "/analyst" },
    ],
  },
  {
    label: "Validation",
    items: [
      { label: "Experiment Studio", href: "/experiment-studio" },
      { label: "Experiments", href: "/experiments" },
      { label: "Runs", href: "/runs" },
      { label: "Domain Packs", href: "/domain-packs" },
    ],
  },
  {
    label: "Assurance",
    items: [
      { label: "Evidence Vault", href: "/evidence-vault" },
      { label: "Controls", href: "/controls" },
      { label: "Assets", href: "/assets" },
      { label: "Revalidation", href: "/revalidation" },
    ],
  },
  {
    label: "Governance",
    items: [
      { label: "Approvals", href: "/approvals" },
      { label: "Audit Trail", href: "/audit-trail" },
    ],
  },
  {
    label: "System",
    items: [
      { label: "Users", href: "/users" },
      { label: "Integrations", href: "/integrations" },
      { label: "Health", href: "/health" },
      { label: "Legacy Dashboard", href: "/legacy-dashboard" },
    ],
  },
];
