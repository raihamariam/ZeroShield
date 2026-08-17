import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { StatusPill } from "./StatusPill";

describe("StatusPill", () => {
  it("renders a title-cased label for a known status", () => {
    render(<StatusPill status="ready_for_review" />);
    expect(screen.getByText("Ready For Review")).toBeInTheDocument();
  });

  it("falls back to neutral styling for an unrecognised status rather than guessing", () => {
    render(<StatusPill status="some_future_status" />);
    const el = screen.getByText("Some Future Status");
    expect(el.className).toContain("bg-surface-muted");
  });

  it("keeps the VPN-adjacent priority labels readable", () => {
    render(<StatusPill status="critical" />);
    expect(screen.getByText("Critical").className).toContain("bg-danger-bg");
  });
});
