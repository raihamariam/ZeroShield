import { adminCredentials, bootstrapUser, expect, login, loginAsAdmin, test } from "../fixtures";

/**
 * Governance acceptance suite (formerly named phase6-acceptance.spec.ts,
 * with scenarios labelled A-H) - eight browser-driven checks covering the
 * UI-facing features V2 Phase 6 added on top of the Phase 4 core journey
 * (already covered by full-lifecycle.spec.ts): local auth, RBAC, self-
 * approval blocking, the immutable audit trail, AI advisory-only
 * assessments, revalidation, threat-intelligence sync, and post-auth
 * graceful degradation.
 *
 * Renamed and relabelled "Governance 1-8" (final release verification
 * pass) to stop implying these were ever the literal "Phase 6 acceptance
 * gate A-H" - that specific, authoritative eight-scenario list (fresh-DB
 * VPN flow, Telecom flow, denied-run, self-approval, regression/
 * revalidation, AI-disabled, MinIO-failure, worker-restart) lives in
 * tests/integration/test_v2_release_acceptance.py instead, since several of
 * those scenarios need infrastructure manipulation (stopping MinIO,
 * restarting the worker container) that a browser-driven Playwright test
 * isn't a natural fit for. See docs/TESTING.md for how the two suites
 * relate. Needs the full docker-compose stack and one bootstrap ADMIN
 * account - see e2e/README.md. Only runs when RUN_E2E_LIVE=1.
 */

test.describe("Governance 1 - authentication and session lifecycle", () => {
  test("unauthenticated access redirects to login, login/logout round-trip works", async ({ page }) => {
    await page.goto("/audit-trail");
    await expect(page).toHaveURL(/\/login/);

    const { username, password } = adminCredentials();
    await login(page, username, password);
    await expect(page).not.toHaveURL(/\/login/);

    await page.goto("/");
    await page.getByRole("button", { name: /Sign out|Log out/i }).click();
    await expect(page).toHaveURL(/\/login/);

    await page.goto("/audit-trail");
    await expect(page).toHaveURL(/\/login/);
  });
});

test.describe("Governance 2 - RBAC is enforced, not just hidden, for a VIEWER", () => {
  test("a VIEWER sees no mutating controls, and the underlying route still rejects a direct attempt", async ({
    page,
    browser,
  }) => {
    await loginAsAdmin(page);
    const viewer = await bootstrapUser(page, "viewer", "rbac");

    const viewerContext = await browser.newContext();
    const viewerPage = await viewerContext.newPage();
    await login(viewerPage, viewer.username, viewer.password);

    await viewerPage.goto("/users");
    await expect(viewerPage.getByRole("button", { name: "Create user" })).toHaveCount(0);

    // Integrations page's "Trigger sync" button is also hidden for VIEWER
    // now (final fix pass) - server-side RBAC (POST /intelligence/sync ->
    // RESEARCHER/ADMIN only) remains the actual enforcement boundary either
    // way; see tests/security/test_rbac_hardening.py's VIEWER -> 403
    // coverage and the direct-API assertion below.
    await viewerPage.goto("/integrations");
    await expect(viewerPage.getByRole("button", { name: "Trigger sync" })).toHaveCount(0);

    // Belt-and-braces: even a direct, script-issued request (bypassing any
    // client-side hiding entirely) must still be rejected server-side.
    const response = await viewerPage.request.post("/api/users", {
      data: { username: "should-not-be-created", password: "irrelevant-password-1", role: "viewer" },
    });
    expect(response.status()).toBe(403);

    await viewerContext.close();
  });
});

test.describe("Governance 3 - self-approval is blocked; a different REVIEWER can approve", () => {
  test("the RESEARCHER who created a version cannot approve it themselves", async ({ page, browser }) => {
    await loginAsAdmin(page);
    const researcher = await bootstrapUser(page, "researcher", "self-approve");
    const reviewer = await bootstrapUser(page, "reviewer", "self-approve");

    const researcherContext = await browser.newContext();
    const researcherPage = await researcherContext.newPage();
    await login(researcherPage, researcher.username, researcher.password);

    await researcherPage.goto("/priority-queue");
    const firstCveLink = researcherPage.locator("table tbody tr").first().getByRole("link").first();
    const cveId = (await firstCveLink.textContent())?.trim();
    test.skip(!cveId, "No priority-queue candidates seeded - nothing to validate against.");
    await firstCveLink.click();
    await researcherPage.getByRole("link", { name: "Validate this CVE" }).click();

    await researcherPage.getByRole("button", { name: /VPN|Telecom/ }).first().click();
    await researcherPage.getByRole("button", { name: "Look up & add" }).click();
    await researcherPage.getByLabel("Trust boundary").fill("pre-authentication network boundary");
    // Not { exact: true }: FormField renders required labels as e.g. "Root cause *" (a
    // visible, aria-hidden asterisk) - getByLabel matches the label's raw text content,
    // which includes that asterisk, so an exact match against "Root cause" alone can
    // never resolve. Each of these is the only element with this label mounted at its
    // step, so the plain substring match stays unambiguous.
    await researcherPage.getByLabel("Root cause").selectOption({ index: 1 });
    await researcherPage.getByLabel("Vendor mitigation").fill("Vendor ships a rate limiter.");
    await researcherPage.getByLabel("Mitigation gap").fill("Rate limiter does not validate request shape.");
    await researcherPage.getByLabel("Source URLs (one per line)").fill("https://example.com/advisory");
    await researcherPage.getByRole("button", { name: "Next", exact: true }).click();
    // Domain pack/template are not auto-selected (StepDomainTemplate always requires an
    // explicit click) - each domain has exactly one registered pack and that pack exactly
    // one template, so picking the first (only) option of each is deterministic.
    await researcherPage.getByRole("button", { name: /Domain Pack/ }).first().click();
    await researcherPage.locator("h2:has-text('Validation template') + div button").first().click();
    await researcherPage.getByRole("button", { name: "Next", exact: true }).click();
    await researcherPage.getByLabel("Title").fill("Governance 3 self-approval-block check");
    await researcherPage.getByLabel("Description").fill("Created by governance-acceptance.spec.ts Governance 3.");
    await researcherPage.getByRole("button", { name: "Next", exact: true }).click();
    await researcherPage.getByRole("button", { name: "Preview dataset" }).click();
    await expect(researcherPage.getByText(/cases · sha256/)).toBeVisible();
    await researcherPage.getByRole("button", { name: "Next", exact: true }).click();
    // Metrics to collect has no default selection either - stepMetricsErrors requires at
    // least one, and StepStrategyMetrics never pre-selects any. Click the first.
    await researcherPage.locator("h2:has-text('Metrics to collect') + div button").first().click();
    await researcherPage.getByRole("button", { name: "Next", exact: true }).click();
    await researcherPage.getByLabel("Failure pattern").selectOption({ index: 1 });
    await researcherPage.getByLabel("Root cause").selectOption({ index: 1 });
    await researcherPage.getByLabel("Vendor mitigation").fill("Vendor ships a rate limiter.");
    await researcherPage.getByLabel("Mitigation gap").fill("Rate limiter does not validate request shape.");
    await researcherPage.getByLabel("Research question").fill("Is self-approval blocked for a non-ADMIN creator?");
    await researcherPage.getByLabel("Hypothesis").fill("The REVIEWER role check rejects the creator's own approval.");
    await researcherPage.getByRole("button", { name: "Next", exact: true }).click();
    await researcherPage.getByRole("button", { name: "Save draft" }).click();
    await expect(researcherPage.getByText(/Draft saved:/)).toBeVisible();
    await researcherPage.getByRole("button", { name: "Submit for review" }).click();
    // page.goto(href), not .click(), wrapped in toPass(): see full-lifecycle.spec.ts's
    // identical comment - a simulated click on this plain <a href> intermittently 404s
    // the exact same URL that goto() and a fresh tab render correctly (no app code in the
    // click path at all), and under sustained sequential load `next dev` can itself drop
    // an RSC stream mid-render and needs a retried navigation - real dev-server
    // infrastructure flakiness, not a weakened assertion.
    const viewVersionHref = await researcherPage.getByRole("link", { name: "View version" }).getAttribute("href");
    await expect(async () => {
      await researcherPage.goto(viewVersionHref!);
      await expect(researcherPage.getByRole("button", { name: "Start review" })).toBeVisible({ timeout: 5_000 });
    }).toPass({ timeout: 60_000 });
    const approvalUrl = researcherPage.url();

    await researcherPage.getByRole("button", { name: "Start review" }).click();
    const approveButton = researcherPage.getByRole("button", { name: "Approve" });
    if (await approveButton.count()) {
      await approveButton.click();
      await expect(researcherPage.getByText(/self.?approval/i)).toBeVisible();
    }

    const reviewerContext = await browser.newContext();
    const reviewerPage = await reviewerContext.newPage();
    await login(reviewerPage, reviewer.username, reviewer.password);
    await reviewerPage.goto(approvalUrl);
    await reviewerPage.getByRole("button", { name: "Approve" }).click();
    await expect(reviewerPage.getByText("approved", { exact: false }).first()).toBeVisible();

    await researcherContext.close();
    await reviewerContext.close();
  });
});

test.describe("Governance 4 - the audit trail records what actually happened", () => {
  test("login and user-creation events are visible to an ADMIN in the audit trail", async ({ page }) => {
    await loginAsAdmin(page);
    const marker = await bootstrapUser(page, "viewer", "audit-check");

    await page.goto("/audit-trail?action=user.created");
    await expect(page.getByText(marker.username)).toBeVisible();

    await page.goto("/audit-trail?action=auth.login_success");
    await expect(page.getByRole("cell", { name: /admin/i }).first()).toBeVisible();
  });
});

test.describe("Governance 5 - AI Research Analyst is advisory-only", () => {
  test("an AI assessment is created unreviewed and only a REVIEWER can mark it reviewed", async ({ page, browser }) => {
    await loginAsAdmin(page);
    const researcher = await bootstrapUser(page, "researcher", "ai-advisory");
    const reviewer = await bootstrapUser(page, "reviewer", "ai-advisory");

    await page.goto("/vulnerabilities");
    const firstCveLink = page.locator("table tbody tr").first().getByRole("link").first();
    const cveId = (await firstCveLink.textContent())?.trim();
    test.skip(!cveId, "No vulnerabilities seeded - nothing to run an AI assessment against.");

    const researcherContext = await browser.newContext();
    const researcherPage = await researcherContext.newPage();
    await login(researcherPage, researcher.username, researcher.password);
    await researcherPage.goto(`/vulnerabilities/${cveId}`);
    await researcherPage.getByRole("button", { name: "Analyze mitigation gap" }).click();
    await expect(researcherPage.getByText(/unreviewed/i).first()).toBeVisible({ timeout: 30_000 });

    const reviewerContext = await browser.newContext();
    const reviewerPage = await reviewerContext.newPage();
    await login(reviewerPage, reviewer.username, reviewer.password);
    await reviewerPage.goto(`/vulnerabilities/${cveId}`);
    await reviewerPage.getByRole("button", { name: "Mark reviewed" }).first().click();
    await expect(reviewerPage.getByText(/unreviewed/i)).toHaveCount(0);

    await researcherContext.close();
    await reviewerContext.close();
  });
});

test.describe("Governance 6 - revalidation: scan, then a REVIEWER decides", () => {
  test("scanning raises candidates deterministically and a decision updates their status", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/revalidation");
    await page.getByRole("button", { name: "Scan for revalidation triggers" }).click();
    await expect(page.getByText(/Scanned \d+ control/)).toBeVisible({ timeout: 30_000 });

    const approveButton = page.getByRole("button", { name: "Approve" }).first();
    test.skip((await approveButton.count()) === 0, "No revalidation candidates raised - nothing to decide on.");
    await approveButton.click();
    await page.goto("/revalidation?status=approved");
    await expect(page.locator("table tbody tr").first()).toBeVisible();
  });
});

test.describe("Governance 7 - threat-intelligence sync reaches Integrations", () => {
  test("triggering a sync queues it and it eventually appears with a terminal status", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/integrations");
    await page.getByRole("button", { name: "Trigger sync" }).first().click();
    await expect(page.getByText(/Queued: SYNC-/)).toBeVisible();

    await expect(async () => {
      await page.reload();
      await expect(page.getByText(/Completed|Partial|Failed/).first()).toBeVisible();
    }).toPass({ timeout: 60_000 });
  });
});

test.describe("Governance 8 - an authenticated session degrades gracefully, never crashes", () => {
  test("an unknown CVE 404s cleanly and a mid-session cookie loss redirects to login, not a crash screen", async ({
    page,
  }) => {
    await loginAsAdmin(page);
    const response = await page.goto("/vulnerabilities/CVE-0000-00000");
    expect(response?.status()).not.toBe(500);
    await expect(page.getByText(/Application error/i)).toHaveCount(0);

    await page.context().clearCookies();
    await page.goto("/audit-trail");
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByText(/Application error/i)).toHaveCount(0);
  });
});
