import { expect, test } from "@playwright/test";

/**
 * The Phase 4 brief's core acceptance scenario: view a priority CVE, create an experiment,
 * submit it for review and approve it, start a run, watch its live state, then view the
 * verdict and evidence - all without touching PowerShell, Swagger, or the filesystem.
 *
 * Requires a live backend with the full docker-compose stack (Postgres, RabbitMQ, worker,
 * a running API) and at least one ingested, supported-domain CVE. Only runs when
 * RUN_E2E_LIVE=1 - see playwright.config.ts and e2e/README.md. NOT executed in the session
 * that wrote this spec (no Docker daemon was available in that sandbox) - treat it as a
 * documented, ready-to-run scenario rather than a passing regression test until it has
 * actually been run once against a live stack.
 */

test("CVE -> Experiment Studio draft -> approve -> run -> verdict -> evidence", async ({ page }) => {
  await page.goto("/priority-queue");
  const firstCveLink = page.locator("table tbody tr").first().getByRole("link").first();
  const cveId = (await firstCveLink.textContent())?.trim();
  test.skip(!cveId, "No priority-queue candidates seeded - nothing to validate against.");
  await firstCveLink.click();
  await expect(page.getByRole("heading", { name: cveId! })).toBeVisible();
  await page.getByRole("link", { name: "Validate this CVE" }).click();
  await expect(page).toHaveURL(new RegExp(`/experiment-studio\\?cve=${cveId}`));

  await page.getByRole("button", { name: /VPN|Telecom/ }).first().click();
  await page.getByRole("button", { name: "Look up & add" }).click();
  await page.getByLabel("Trust boundary").fill("pre-authentication network boundary");
  await page.getByLabel("Vendor mitigation").fill("Vendor ships a rate limiter.");
  await page.getByLabel("Mitigation gap").fill("Rate limiter does not validate request shape.");
  await page.getByLabel("Source URLs (one per line)").fill("https://example.com/advisory");
  await page.getByRole("button", { name: "Next" }).click();

  await page.getByRole("button", { name: "Next" }).click(); // domain pack/template auto-selected
  await page.getByLabel("Title").fill("E2E validation experiment");
  await page.getByLabel("Description").fill("Created by the Playwright full-lifecycle spec.");
  await page.getByRole("button", { name: "Next" }).click();

  await page.getByRole("button", { name: "Preview dataset" }).click();
  await expect(page.getByText(/cases · sha256/)).toBeVisible();
  await page.getByRole("button", { name: "Next" }).click();

  await page.getByRole("button", { name: "Next" }).click(); // strategy/metrics defaults

  await page.getByLabel("Failure pattern").selectOption({ index: 1 });
  await page.getByLabel("Root cause", { exact: true }).selectOption({ index: 1 });
  await page.getByLabel("Vendor mitigation", { exact: true }).fill("Vendor ships a rate limiter.");
  await page.getByLabel("Mitigation gap", { exact: true }).fill("Rate limiter does not validate request shape.");
  await page.getByLabel("Research question").fill("Does the mitigation reduce malformed-request acceptance?");
  await page.getByLabel("Hypothesis").fill("The mitigation blocks more malformed cases than baseline.");
  await page.getByLabel("Your name").fill("Playwright E2E");
  await page.getByRole("button", { name: "Next" }).click();

  await page.getByRole("button", { name: "Save draft" }).click();
  await expect(page.getByText(/Draft saved:/)).toBeVisible();
  await page.getByRole("button", { name: "Submit for review" }).click();
  await expect(page.getByText("Submitted for review.")).toBeVisible();

  await page.getByRole("link", { name: "View version" }).click();
  await expect(page).toHaveURL(/\/approvals\//);
  await page.getByLabel("Your name").fill("Playwright E2E Reviewer");
  await page.getByRole("button", { name: "Start review" }).click();
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText("approved", { exact: false }).first()).toBeVisible();

  const experimentLink = page.getByRole("link", { name: /^ZC-/ }).first();
  await experimentLink.click();
  await page.getByLabel("Execution context", { exact: false });
  await page.getByRole("button", { name: "Submit run" }).click();
  await expect(page).toHaveURL(/\/runs\/JOB-/);

  await expect(page.getByText("Complete")).toBeVisible({ timeout: 120_000 });
  const experimentId = page.url(); // captured for the follow-up navigation below
  await page.getByRole("link", { name: "View full results & verdict →" }).click();
  await expect(page.getByText(/Effective|Partially Effective|Ineffective|Regression|Inconclusive/)).toBeVisible();

  await page.goBack();
  await page.getByRole("link", { name: "View evidence →" }).click();
  await expect(page.getByText("Integrity verified").first()).toBeVisible();
  await expect(page.getByRole("link", { name: /Download evidence bundle/ })).toBeVisible();
  void experimentId;
});
