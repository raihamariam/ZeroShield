import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ErrorState } from "./ErrorState";
import { ApiError } from "@/lib/api/client";

describe("ErrorState", () => {
  it("shows a distinct message when the backend is unreachable", () => {
    render(<ErrorState error={new ApiError(0, null)} />);
    expect(screen.getByText("ZeroShield API is unreachable")).toBeInTheDocument();
  });

  it("shows a not-found message for a 404 with the backend's own detail", () => {
    render(<ErrorState error={new ApiError(404, { error: "not_found", detail: "no experiment 'X'" })} />);
    expect(screen.getByText("Not found")).toBeInTheDocument();
    expect(screen.getByText("no experiment 'X'")).toBeInTheDocument();
  });

  it("includes the HTTP status for other failures", () => {
    render(<ErrorState error={new ApiError(500, { error: "server_error", detail: "boom" })} />);
    expect(screen.getByText("Request failed (HTTP 500)")).toBeInTheDocument();
  });

  it("degrades gracefully for a non-ApiError exception", () => {
    render(<ErrorState error={new Error("unexpected")} />);
    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
  });
});
