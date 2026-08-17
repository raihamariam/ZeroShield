import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiFetch } from "./client";

function mockFetchOnce(response: Partial<Response> & { json?: () => Promise<unknown> }) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: response.ok ?? true,
      status: response.status ?? 200,
      json: response.json ?? (async () => ({})),
    } as Response)
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiFetch", () => {
  it("returns the decoded JSON body on success", async () => {
    mockFetchOnce({ ok: true, status: 200, json: async () => ({ hello: "world" }) });
    const result = await apiFetch<{ hello: string }>("/health");
    expect(result).toEqual({ hello: "world" });
  });

  it("throws ApiError with the backend's structured detail on a non-2xx response", async () => {
    mockFetchOnce({
      ok: false,
      status: 404,
      json: async () => ({ detail: { error: "not_found", detail: "no experiment 'X'" } }),
    });
    await expect(apiFetch("/experiments/X")).rejects.toMatchObject({
      status: 404,
      body: { error: "not_found", detail: "no experiment 'X'" },
    });
  });

  it("marks a network failure as unreachable (status 0), never a decoded error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new TypeError("fetch failed"))
    );
    const error = (await apiFetch("/health").catch((e: unknown) => e)) as ApiError;
    expect(error).toBeInstanceOf(ApiError);
    expect(error.isUnreachable).toBe(true);
    expect(error.status).toBe(0);
  });

  it("treats FastAPI's plain validation-error list as a stringified detail, not a crash", async () => {
    mockFetchOnce({
      ok: false,
      status: 422,
      json: async () => ({ detail: [{ loc: ["body", "seed"], msg: "field required", type: "missing" }] }),
    });
    const error = (await apiFetch("/datasets/generate").catch((e: unknown) => e)) as ApiError;
    expect(error.status).toBe(422);
    expect(error.body?.error).toBe("validation_error");
  });
});
