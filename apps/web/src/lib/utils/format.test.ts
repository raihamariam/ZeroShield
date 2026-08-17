import { describe, expect, it } from "vitest";
import { formatDomain, formatMs, formatNumber, formatPercent, titleCase } from "./format";

describe("formatPercent", () => {
  it("formats a 0-1 rate as a percentage", () => {
    expect(formatPercent(0.5)).toBe("50.0%");
    expect(formatPercent(1)).toBe("100.0%");
    expect(formatPercent(0)).toBe("0.0%");
  });

  it("renders an em dash for missing values", () => {
    expect(formatPercent(null)).toBe("—");
    expect(formatPercent(undefined)).toBe("—");
    expect(formatPercent(Number.NaN)).toBe("—");
  });
});

describe("formatNumber", () => {
  it("formats with the requested fraction digits", () => {
    expect(formatNumber(7.891, 1)).toBe("7.9");
    expect(formatNumber(7)).toBe("7");
  });

  it("renders an em dash for missing values", () => {
    expect(formatNumber(null)).toBe("—");
  });
});

describe("formatMs", () => {
  it("keeps sub-second values in ms", () => {
    expect(formatMs(250)).toBe("250 ms");
  });

  it("switches to seconds at 1000ms", () => {
    expect(formatMs(1500)).toBe("1.50 s");
  });
});

describe("titleCase", () => {
  it("title-cases snake_case and kebab-case alike", () => {
    expect(titleCase("block_rate")).toBe("Block Rate");
    expect(titleCase("ready-for-review")).toBe("Ready For Review");
  });
});

describe("formatDomain", () => {
  it("keeps VPN as an uppercase acronym", () => {
    expect(formatDomain("VPN")).toBe("VPN");
    expect(formatDomain("vpn")).toBe("VPN");
  });

  it("title-cases other domains", () => {
    expect(formatDomain("TELECOM")).toBe("Telecom");
  });
});
