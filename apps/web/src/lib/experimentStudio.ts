/** RootCauseCategory (zeroshield.models.enums.RootCauseCategory) has no API listing
 * endpoint - these are the fixed, authoritative enum values themselves. */
export const ROOT_CAUSE_CATEGORIES: { value: string; label: string }[] = [
  { value: "memory_safety_failure", label: "Memory safety failure" },
  { value: "parser_message_handling_failure", label: "Parser/message handling failure" },
  { value: "input_validation_failure", label: "Input validation failure" },
  { value: "authentication_logic_error", label: "Authentication logic error" },
  { value: "authentication_logic_flaw", label: "Authentication logic flaw" },
  { value: "authorization_access_control_failure", label: "Authorization/access control failure" },
  { value: "injection_flaw", label: "Injection flaw" },
  { value: "unsafe_command_or_code_execution", label: "Unsafe command or code execution" },
];

export const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,7}$/;
export const EXPERIMENT_ID_PATTERN = /^ZC-(VPN|TELECOM)-EXP-\d{3,}$/;

export function suggestNextExperimentId(domain: "VPN" | "TELECOM", existingIds: string[]): string {
  const prefix = `ZC-${domain}-EXP-`;
  let max = 0;
  for (const id of existingIds) {
    if (!id.startsWith(prefix)) continue;
    const n = Number.parseInt(id.slice(prefix.length), 10);
    if (Number.isFinite(n) && n > max) max = n;
  }
  return `${prefix}${String(max + 1).padStart(3, "0")}`;
}

export interface CveRowState {
  key: string;
  cve_id: string;
  cvss_score: string;
  cisa_kev: boolean;
  epss_score: string;
  trust_boundary: string;
  root_cause: string;
  vendor_mitigation: string;
  mitigation_gap: string;
  source_urls: string;
  retrieved_date: string;
}

export function emptyCveRow(key: string): CveRowState {
  return {
    key,
    cve_id: "",
    cvss_score: "",
    cisa_kev: false,
    epss_score: "",
    trust_boundary: "",
    root_cause: "",
    vendor_mitigation: "",
    mitigation_gap: "",
    source_urls: "",
    retrieved_date: new Date().toISOString().slice(0, 10),
  };
}

export function validateCveRow(row: CveRowState): string[] {
  const errors: string[] = [];
  if (!CVE_ID_PATTERN.test(row.cve_id)) errors.push("CVE ID must look like CVE-YYYY-NNNN.");
  if (!row.trust_boundary.trim()) errors.push("Trust boundary is required.");
  if (!row.root_cause) errors.push("Root cause is required.");
  if (!row.vendor_mitigation.trim()) errors.push("Vendor mitigation is required.");
  if (!row.mitigation_gap.trim()) errors.push("Mitigation gap is required.");
  if (row.source_urls.split("\n").map((s) => s.trim()).filter(Boolean).length === 0) {
    errors.push("At least one source URL is required.");
  }
  if (!row.retrieved_date) errors.push("Retrieved date is required.");
  if (row.cvss_score && (Number(row.cvss_score) < 0 || Number(row.cvss_score) > 10)) {
    errors.push("CVSS score must be between 0 and 10.");
  }
  if (row.epss_score && (Number(row.epss_score) < 0 || Number(row.epss_score) > 1)) {
    errors.push("EPSS score must be between 0 and 1.");
  }
  return errors;
}

export function cveRowToRequest(row: CveRowState, domain: "VPN" | "TELECOM") {
  return {
    cve_id: row.cve_id.toUpperCase(),
    domain,
    cvss_score: row.cvss_score ? Number(row.cvss_score) : null,
    cisa_kev: row.cisa_kev,
    epss_score: row.epss_score ? Number(row.epss_score) : null,
    trust_boundary: row.trust_boundary.trim(),
    root_cause: row.root_cause,
    vendor_mitigation: row.vendor_mitigation.trim(),
    mitigation_gap: row.mitigation_gap.trim(),
    source_urls: row.source_urls
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean),
    retrieved_date: row.retrieved_date,
  };
}
