import { describe, expect, it } from "vitest";
import { cveRowToRequest, emptyCveRow, suggestNextExperimentId, validateCveRow } from "./experimentStudio";

describe("suggestNextExperimentId", () => {
  it("suggests 001 when nothing exists for the domain", () => {
    expect(suggestNextExperimentId("VPN", [])).toBe("ZC-VPN-EXP-001");
  });

  it("increments past the highest existing id in that domain", () => {
    expect(suggestNextExperimentId("VPN", ["ZC-VPN-EXP-001", "ZC-VPN-EXP-003", "ZC-TELECOM-EXP-099"])).toBe("ZC-VPN-EXP-004");
  });

  it("never collides across domains", () => {
    expect(suggestNextExperimentId("TELECOM", ["ZC-VPN-EXP-050"])).toBe("ZC-TELECOM-EXP-001");
  });

  it("widens past 3 digits once the sequence exceeds 999", () => {
    expect(suggestNextExperimentId("VPN", ["ZC-VPN-EXP-999"])).toBe("ZC-VPN-EXP-1000");
  });
});

describe("validateCveRow", () => {
  it("flags every required field on an empty row", () => {
    const errors = validateCveRow(emptyCveRow("k"));
    expect(errors.length).toBeGreaterThan(0);
  });

  it("rejects a malformed CVE ID", () => {
    const row = { ...emptyCveRow("k"), cve_id: "not-a-cve" };
    expect(validateCveRow(row)).toContain("CVE ID must look like CVE-YYYY-NNNN.");
  });

  it("passes a fully-filled-in row", () => {
    const row = {
      ...emptyCveRow("k"),
      cve_id: "CVE-2024-12345",
      trust_boundary: "pre-auth",
      root_cause: "input_validation_failure",
      vendor_mitigation: "vendor patch",
      mitigation_gap: "gap",
      source_urls: "https://example.com/advisory",
    };
    expect(validateCveRow(row)).toEqual([]);
  });

  it("rejects an out-of-range CVSS score", () => {
    const row = {
      ...emptyCveRow("k"),
      cve_id: "CVE-2024-12345",
      trust_boundary: "pre-auth",
      root_cause: "input_validation_failure",
      vendor_mitigation: "vendor patch",
      mitigation_gap: "gap",
      source_urls: "https://example.com/advisory",
      cvss_score: "11",
    };
    expect(validateCveRow(row)).toContain("CVSS score must be between 0 and 10.");
  });
});

describe("cveRowToRequest", () => {
  it("splits newline-separated source URLs into an array and uppercases the CVE ID", () => {
    const row = {
      ...emptyCveRow("k"),
      cve_id: "cve-2024-12345",
      source_urls: "https://a.example\n\nhttps://b.example\n",
    };
    const request = cveRowToRequest(row, "VPN");
    expect(request.cve_id).toBe("CVE-2024-12345");
    expect(request.source_urls).toEqual(["https://a.example", "https://b.example"]);
    expect(request.domain).toBe("VPN");
  });

  it("converts blank score strings to null rather than NaN", () => {
    const request = cveRowToRequest(emptyCveRow("k"), "VPN");
    expect(request.cvss_score).toBeNull();
    expect(request.epss_score).toBeNull();
  });
});
